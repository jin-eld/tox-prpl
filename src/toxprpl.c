/*
 *  Copyright (c) 2013 Sergey 'Jin' Bostandzhyan <jin at mediatomb dot cc>
 *
 *  tox-prlp - libpurple protocol plugin or Tox (see http://tox.im)
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  This plugin is based on the Nullprpl mockup from Pidgin / Finch / libpurple
 *  which is disributed under GPL v2 or later.  See http://pidgin.im/
 */

#ifdef HAVE_CONFIG_H
    #include "autoconfig.h"
#endif

#include <stdarg.h>
#include <string.h>
#include <time.h>

#include <errno.h>
#include <sys/types.h>
#ifdef __WIN32__
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <sys/socket.h>
    #include <netdb.h>
    #include <arpa/inet.h>
#endif

#ifndef O_BINARY
    #ifdef _O_BINARY
        #define O_BINARY _O_BINARY
    #else
        #define O_BINARY 0
    #endif
#endif

#include <sys/stat.h>
#include <fcntl.h>

#include <glib.h>
#include <glib/gstdio.h>

#include <tox/tox.h>
#include <network.h>

#define PURPLE_PLUGINS

#include <account.h>
#include <accountopt.h>
#include <blist.h>
#include <cmds.h>
#include <conversation.h>
#include <connection.h>
#include <debug.h>
#include <notify.h>
#include <privacy.h>
#include <prpl.h>
#include <roomlist.h>
#include <request.h>
#include <status.h>
#include <util.h>
#include <version.h>

#define _(msg) msg // might add gettext later

#define TOXPRPL_ID "prpl-jin_eld-tox"
#define DEFAULT_SERVER_KEY "5CD7EB176C19A2FD840406CD56177BB8E75587BB366F7BB3004B19E3EDC04143"
#define DEFAULT_SERVER_PORT 33445
#define DEFAULT_SERVER_IP   "192.184.81.118"

#define DEFAULT_REQUEST_MESSAGE _("Please allow me to add you as a friend!")

#define MAX_ACCOUNT_DATA_SIZE   1*1024*1024
static const char *g_HEX_CHARS = "0123456789abcdef";

typedef struct
{
    PurpleStatusPrimitive primitive;
    uint8_t tox_status;
    gchar *id;
    gchar *title;
} toxprpl_status;

typedef struct
{
    int tox_friendlist_number;
} toxprpl_buddy_data;

typedef struct
{
    PurpleConnection *gc;
    char *buddy_key;
} toxprpl_accept_friend_data;

typedef struct
{
    Tox *tox;
    guint tox_timer;
    guint connection_timer;
    guint connected;
    PurpleCmdId myid_command_id;
    PurpleCmdId nick_command_id;
} toxprpl_plugin_data;

#define TOXPRPL_MAX_STATUS          4
#define TOXPRPL_STATUS_ONLINE       0
#define TOXPRPL_STATUS_AWAY         1
#define TOXPRPL_STATUS_BUSY         2
#define TOXPRPL_STATUS_OFFLINE      3

static toxprpl_status toxprpl_statuses[] =
{
    {
        PURPLE_STATUS_AVAILABLE, TOXPRPL_STATUS_ONLINE,
        "tox_online", _("Online")
    },
    {
        PURPLE_STATUS_AWAY, TOXPRPL_STATUS_AWAY,
        "tox_away", _("Away")
    },
    {
        PURPLE_STATUS_UNAVAILABLE, TOXPRPL_STATUS_BUSY,
        "tox_busy", _("Busy")
    },
    {
        PURPLE_STATUS_OFFLINE, TOXPRPL_STATUS_OFFLINE,
        "tox_offline", _("Offline")
    }
};

/*
 * stores offline messages that haven't been delivered yet. maps username
 * (char *) to GList * of GOfflineMessages. initialized in toxprpl_init.
 */
GHashTable* goffline_messages = NULL;

typedef struct
{
    char *from;
    char *message;
    time_t mtime;
    PurpleMessageFlags flags;
} GOfflineMessage;

static void toxprpl_add_to_buddylist(toxprpl_accept_friend_data *data);
static void toxprpl_do_not_add_to_buddylist(toxprpl_accept_friend_data *data);

static void toxprpl_login(PurpleAccount *acct);
static void toxprpl_query_buddy_info(gpointer data, gpointer user_data);
static void toxprpl_set_status(PurpleAccount *account, PurpleStatus *status);

// utilitis

// returned buffer must be freed by the caller
static char *toxprpl_data_to_hex_string(const unsigned char *data,
                                        const size_t len)
{
    unsigned char *chars;
    unsigned char hi, lo;
    size_t i;
    char *buf = malloc((len * 2) + 1);
    char *p = buf;
    chars = (unsigned char *)data;
    chars = (unsigned char *)data;
    for (i = 0; i < len; i++)
    {
        unsigned char c = chars[i];
        hi = c >> 4;
        lo = c & 0xF;
        *p = g_HEX_CHARS[hi];
        p++;
        *p = g_HEX_CHARS[lo];
        p++;
    }
    buf[len*2] = '\0';
    return buf;
}

unsigned char *toxprpl_hex_string_to_data(const char *s)
{
    size_t len = strlen(s);
    unsigned char *buf = malloc(len / 2);
    unsigned char *p = buf;

    size_t i;
    for (i = 0; i < len; i += 2)
    {
        const char *chi = strchr(g_HEX_CHARS, g_ascii_tolower(s[i]));
        const char *clo = strchr(g_HEX_CHARS, g_ascii_tolower(s[i + 1]));
        int hi, lo;
        if (chi)
        {
            hi = chi - g_HEX_CHARS;
        }
        else
        {
            hi = 0;
        }

        if (clo)
        {
            lo = clo - g_HEX_CHARS;
        }
        else
        {
            lo = 0;
        }

        unsigned char ch = (unsigned char)(hi << 4 | lo);
        *p = ch;
        p++;
    }
    return buf;
}

// stay independent from the lib
static int toxprpl_get_status_index(Tox *tox, int fnum, TOX_USERSTATUS status)
{
    switch (status)
    {
        case TOX_USERSTATUS_AWAY:
            return TOXPRPL_STATUS_AWAY;
        case TOX_USERSTATUS_BUSY:
            return TOXPRPL_STATUS_BUSY;
        case TOX_USERSTATUS_NONE:
        case TOX_USERSTATUS_INVALID:
        default:
            if (fnum != -1)
            {
                if (tox_get_friend_connection_status(tox, fnum) == 1)
                {
                    return TOXPRPL_STATUS_ONLINE;
                }
            }
    }
    return TOXPRPL_STATUS_OFFLINE;
}

static TOX_USERSTATUS toxprpl_get_tox_status_from_id(const char *status_id)
{
    int i;
    for (i = 0; i < TOXPRPL_MAX_STATUS; i++)
    {
        if (strcmp(toxprpl_statuses[i].id, status_id) == 0)
        {
            return toxprpl_statuses[i].tox_status;
        }
    }
    return TOX_USERSTATUS_INVALID;
}

/* tox helpers */
static gchar *toxprpl_tox_bin_id_to_string(uint8_t *bin_id)
{
    return toxprpl_data_to_hex_string(bin_id, TOX_CLIENT_ID_SIZE);
}

static gchar *toxprpl_tox_friend_id_to_string(uint8_t *bin_id)
{
    return toxprpl_data_to_hex_string(bin_id, TOX_FRIEND_ADDRESS_SIZE);
}

/* tox specific stuff */
static void on_connectionstatus(Tox *tox, int fnum, uint8_t status,
                                void *user_data)
{
    PurpleConnection *gc = (PurpleConnection *)user_data;
    int tox_status = TOXPRPL_STATUS_OFFLINE;
    if (status == 1)
    {
        tox_status = TOXPRPL_STATUS_ONLINE;
    }

    purple_debug_info("toxprpl", "Friend status change: %d\n", status);
    uint8_t client_id[TOX_CLIENT_ID_SIZE];
    if (tox_get_client_id(tox, fnum, client_id) < 0)
    {
        purple_debug_info("toxprpl", "Could not get id of friend #%d\n",
                          fnum);
        return;
    }

    gchar *buddy_key = toxprpl_tox_bin_id_to_string(client_id);
    PurpleAccount *account = purple_connection_get_account(gc);
    purple_prpl_got_user_status(account, buddy_key,
        toxprpl_statuses[tox_status].id, NULL);
    g_free(buddy_key);
}

static void on_request(uint8_t* public_key, uint8_t* data,
                       uint16_t length, void *user_data)
{
    purple_debug_info("toxprpl", "incoming friend request!\n");
    gchar *dialog_message;
    PurpleConnection *gc = (PurpleConnection *)user_data;

    gchar *buddy_key = toxprpl_tox_bin_id_to_string(public_key);
    purple_debug_info("toxprpl", "Buddy request from %s: %s\n",
                      buddy_key, data);

    PurpleAccount *account = purple_connection_get_account(gc);
    PurpleBuddy *buddy = purple_find_buddy(account, buddy_key);
    if (buddy != NULL)
    {
        purple_debug_info("toxprpl", "Buddy %s already in buddy list!\n",
                          buddy_key);
        g_free(buddy_key);
        return;
    }

    dialog_message = g_strdup_printf("The user %s has sent you a friend "
                                    "request, do you want to add him?",
                                    buddy_key);

    gchar *request_msg = NULL;
    if (length > 0)
    {
        request_msg = g_strndup((const gchar *)data, length);
    }

    toxprpl_accept_friend_data *fdata = g_new0(toxprpl_accept_friend_data, 1);
    fdata->gc = gc;
    fdata->buddy_key = buddy_key;
    purple_request_yes_no(gc, "New friend request", dialog_message,
                          request_msg,
                          PURPLE_DEFAULT_ACTION_NONE,
                          account, NULL,
                          NULL,
                          fdata, // buddy key will be freed elsewhere
                          G_CALLBACK(toxprpl_add_to_buddylist),
                          G_CALLBACK(toxprpl_do_not_add_to_buddylist));
    g_free(dialog_message);
    g_free(request_msg);
}

static void on_friend_action(Tox *tox, int friendnum, uint8_t* string,
                             uint16_t length, void *user_data)
{
    purple_debug_info("toxprpl", "action received\n");
    PurpleConnection *gc = (PurpleConnection *)user_data;

    uint8_t client_id[TOX_CLIENT_ID_SIZE];
    if (tox_get_client_id(tox, friendnum, client_id) < 0)
    {
        purple_debug_info("toxprpl", "Could not get id of friend %d\n",
                          friendnum);
        return;
    }

    gchar *buddy_key = toxprpl_tox_bin_id_to_string(client_id);
    gchar *message = g_strdup_printf("/me %s", string);

    serv_got_im(gc, buddy_key, message, PURPLE_MESSAGE_RECV,
                time(NULL));
    g_free(buddy_key);
    g_free(message);
}

static void on_incoming_message(Tox *tox, int friendnum, uint8_t* string,
                                uint16_t length, void *user_data)
{
    purple_debug_info("toxprpl", "Message received!\n");
    PurpleConnection *gc = (PurpleConnection *)user_data;

    uint8_t client_id[TOX_CLIENT_ID_SIZE];
    if (tox_get_client_id(tox, friendnum, client_id) < 0)
    {
        purple_debug_info("toxprpl", "Could not get id of friend %d\n",
                          friendnum);
        return;
    }

    gchar *buddy_key = toxprpl_tox_bin_id_to_string(client_id);
    serv_got_im(gc, buddy_key, (const char *)string, PURPLE_MESSAGE_RECV,
                time(NULL));
    g_free(buddy_key);
}

static void on_nick_change(Tox *tox, int friendnum, uint8_t* data,
                           uint16_t length, void *user_data)
{
    purple_debug_info("toxprpl", "Nick change!\n");

    PurpleConnection *gc = (PurpleConnection *)user_data;

    uint8_t client_id[TOX_CLIENT_ID_SIZE];
    if (tox_get_client_id(tox, friendnum, client_id) < 0)
    {
        purple_debug_info("toxprpl", "Could not get id of friend %d\n",
                          friendnum);
        return;
    }

    gchar *buddy_key = toxprpl_tox_bin_id_to_string(client_id);
    PurpleAccount *account = purple_connection_get_account(gc);
    PurpleBuddy *buddy = purple_find_buddy(account, buddy_key);
    if (buddy == NULL)
    {
        purple_debug_info("toxprpl", "Ignoring nick change because buddy %s was not found\n", buddy_key);
        g_free(buddy_key);
        return;
    }

    g_free(buddy_key);
    purple_blist_alias_buddy(buddy, (const char *)data);
}

static void on_status_change(Tox *tox, int friendnum, TOX_USERSTATUS userstatus,
                             void *user_data)
{
    purple_debug_info("toxprpl", "Status change: %d\n", userstatus);
    uint8_t client_id[TOX_CLIENT_ID_SIZE];
    if (tox_get_client_id(tox, friendnum, client_id) < 0)
    {
        purple_debug_info("toxprpl", "Could not get id of friend %d\n",
                          friendnum);
        return;
    }

    gchar *buddy_key = toxprpl_tox_bin_id_to_string(client_id);

    PurpleConnection *gc = (PurpleConnection *)user_data;
    PurpleAccount *account = purple_connection_get_account(gc);
    purple_debug_info("toxprpl", "Setting user status for user %s to %s\n",
        buddy_key, toxprpl_statuses[
            toxprpl_get_status_index(tox, friendnum, userstatus)].id);
    purple_prpl_got_user_status(account, buddy_key,
        toxprpl_statuses[
            toxprpl_get_status_index(tox, friendnum, userstatus)].id,
        NULL);
    g_free(buddy_key);
}

static gboolean tox_messenger_loop(gpointer data)
{
    PurpleConnection *gc = (PurpleConnection *)data;
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    if ((plugin != NULL) && (plugin->tox != NULL))
    {
        tox_do(plugin->tox);
    }
    return TRUE;
}

static gboolean tox_connection_check(gpointer gc)
{
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);

    if ((plugin->connected == 0) && tox_isconnected(plugin->tox))
    {
        plugin->connected = 1;
        purple_connection_update_progress(gc, _("Connected"),
                1,   /* which connection step this is */
                2);  /* total number of steps */
        purple_connection_set_state(gc, PURPLE_CONNECTED);
        purple_debug_info("toxprpl", "DHT connected!\n");

        // query status of all buddies
        PurpleAccount *account = purple_connection_get_account(gc);
        GSList *buddy_list = purple_find_buddies(account, NULL);
        g_slist_foreach(buddy_list, toxprpl_query_buddy_info, gc);
        g_slist_free(buddy_list);

        uint8_t our_name[TOX_MAX_NAME_LENGTH];
        uint16_t name_len = tox_get_self_name(plugin->tox, our_name,
                                             TOX_MAX_NAME_LENGTH);
        // bug in the library?
        if (name_len == 0)
        {
            our_name[0] = '\0';
        }

        const char *nick = purple_account_get_string(account, "nickname", NULL);
        if (nick == NULL)
        {
            if (strlen((const char *)our_name) > 0)
            {
                purple_connection_set_display_name(gc, (const char *)our_name);
                purple_account_set_string(account, "nickname",
                                                      (const char *)our_name);
            }
        }
        else
        {
            purple_connection_set_display_name(gc, nick);
            if (strcmp(nick, (const char *)our_name) != 0)
            {
                tox_set_name(plugin->tox, (uint8_t *)nick, strlen(nick) + 1);
            }
        }

        PurpleStatus* status = purple_account_get_active_status(account);
        if(status != NULL)
        {
            purple_debug_info("toxprpl", "(re)setting status\n");
            toxprpl_set_status(account, status);
        }
    }
    else if ((plugin->connected == 1) && !tox_isconnected(plugin->tox))
    {
        plugin->connected = 0;
        purple_debug_info("toxprpl", "DHT disconnected!\n");
        purple_connection_notice(gc,
                _("Connection to DHT server lost, attempging to reconnect..."));
        purple_connection_update_progress(gc, _("Reconnecting..."),
                0,   /* which connection step this is */
                2);  /* total number of steps */
    }
    return TRUE;
}

static void toxprpl_set_status(PurpleAccount *account, PurpleStatus *status)
{
    const char* status_id = purple_status_get_id(status);
    const char *message = purple_status_get_attr_string(status, "message");

    PurpleConnection *gc = purple_account_get_connection(account);
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);

    purple_debug_info("toxprpl", "setting status %s\n", status_id);

    TOX_USERSTATUS tox_status = toxprpl_get_tox_status_from_id(status_id);
    if (tox_status == TOX_USERSTATUS_INVALID)
    {
        purple_debug_info("toxprpl", "status %s is invalid\n", status_id);
        return;
    }

    tox_set_user_status(plugin->tox, tox_status);
    if ((message != NULL) && (strlen(message) > 0))
    {
        tox_set_status_message(plugin->tox, (uint8_t *)message, strlen(message) + 1);
    }
}

// query buddy status
static void toxprpl_query_buddy_info(gpointer data, gpointer user_data)
{
    purple_debug_info("toxprpl", "toxprpl_query_buddy_info\n");
    PurpleBuddy *buddy = (PurpleBuddy *)data;
    PurpleConnection *gc = (PurpleConnection *)user_data;
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);

    toxprpl_buddy_data *buddy_data = purple_buddy_get_protocol_data(buddy);
    if (buddy_data == NULL)
    {
        unsigned char *bin_key = toxprpl_hex_string_to_data(buddy->name);
        int fnum = tox_get_friend_id(plugin->tox, bin_key);
        buddy_data = g_new0(toxprpl_buddy_data, 1);
        buddy_data->tox_friendlist_number = fnum;
        purple_buddy_set_protocol_data(buddy, buddy_data);
        g_free(bin_key);
    }

    PurpleAccount *account = purple_connection_get_account(gc);
    purple_debug_info("toxprpl", "Setting user status for user %s to %s\n",
        buddy->name, toxprpl_statuses[toxprpl_get_status_index(plugin->tox,
            buddy_data->tox_friendlist_number,
            tox_get_user_status(plugin->tox,buddy_data->tox_friendlist_number))].id);
    purple_prpl_got_user_status(account, buddy->name,
        toxprpl_statuses[toxprpl_get_status_index(plugin->tox,
            buddy_data->tox_friendlist_number,
            tox_get_user_status(plugin->tox, buddy_data->tox_friendlist_number))].id,
        NULL);

    uint8_t alias[TOX_MAX_NAME_LENGTH];
    if (tox_get_name(plugin->tox, buddy_data->tox_friendlist_number, alias) == 0)
    {
        purple_blist_alias_buddy(buddy, (const char*)alias);
    }
}

static const char *toxprpl_list_icon(PurpleAccount *acct, PurpleBuddy *buddy)
{
    return "tox";
}

static GList *toxprpl_status_types(PurpleAccount *acct)
{
    GList *types = NULL;
    PurpleStatusType *type;
    int i;

    purple_debug_info("toxprpl", "setting up status types\n");

    for (i = 0; i < TOXPRPL_MAX_STATUS; i++)
    {
        type = purple_status_type_new_with_attrs(toxprpl_statuses[i].primitive,
            toxprpl_statuses[i].id, toxprpl_statuses[i].title, TRUE, TRUE,
            FALSE,
            "message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
            NULL);
        types = g_list_append(types, type);
    }

    return types;
}

static void toxprpl_set_nick_action(PurpleConnection *gc, const char *nickname)
{
    PurpleAccount *account = purple_connection_get_account(gc);
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    if (nickname != NULL)
    {
        purple_connection_set_display_name(gc, nickname);
        tox_set_name(plugin->tox, (uint8_t *)nickname, strlen(nickname) + 1);
        purple_account_set_string(account, "nickname", nickname);
    }
}

static PurpleCmdRet toxprpl_myid_cmd_cb(PurpleConversation *conv,
        const gchar *cmd, gchar **args, gchar **error, void *data)
{
    purple_debug_info("toxprpl", "/myid command detected\n");
    PurpleConnection *gc = (PurpleConnection *)data;
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);

    uint8_t bin_id[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(plugin->tox, bin_id);
    gchar *id = toxprpl_tox_friend_id_to_string(bin_id);

    gchar *message = g_strdup_printf(_("If someone wants to add you, give them "
                                       "this id: %s"), id);

    purple_conversation_write(conv, NULL, message, PURPLE_MESSAGE_SYSTEM,
                              time(NULL));
    g_free(id);
    g_free(message);
    return PURPLE_CMD_RET_OK;
}

static PurpleCmdRet toxprpl_nick_cmd_cb(PurpleConversation *conv,
        const gchar *cmd, gchar **args, gchar **error, void *data)
{
    purple_debug_info("toxprpl", "/nick %s command detected\n", args[0]);
    PurpleConnection *gc = (PurpleConnection *)data;
    toxprpl_set_nick_action(gc, args[0]);
    return PURPLE_CMD_RET_OK;
}

static void toxprpl_sync_add_buddy(PurpleAccount *account, Tox *tox,
                                   int friend_number)
{
    uint8_t alias[TOX_MAX_NAME_LENGTH];
    uint8_t client_id[TOX_CLIENT_ID_SIZE];
    if (tox_get_client_id(tox, friend_number, client_id) < 0)
    {
        purple_debug_info("toxprpl", "Could not get id of friend #%d\n",
                          friend_number);
        return;
    }

    gchar *buddy_key = toxprpl_tox_bin_id_to_string(client_id);


    PurpleBuddy *buddy;
    if ((tox_get_name(tox, friend_number, alias) == 0) &&
        (strlen((const char *)alias) > 0))
    {
        purple_debug_info("toxprpl", "Got friend alias %s\n", alias);
        buddy = purple_buddy_new(account, buddy_key, (const char*)alias);
    }
    else
    {
        purple_debug_info("toxprpl", "Adding [%s]\n", buddy_key);
        buddy = purple_buddy_new(account, buddy_key, NULL);
    }

    toxprpl_buddy_data *buddy_data = g_new0(toxprpl_buddy_data, 1);
    buddy_data->tox_friendlist_number = friend_number;
    purple_buddy_set_protocol_data(buddy, buddy_data);
    purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    TOX_USERSTATUS userstatus = tox_get_user_status(tox, friend_number);
    purple_debug_info("toxprpl", "Friend %s has status %d\n", buddy_key,
                      userstatus);
    purple_prpl_got_user_status(account, buddy_key,
        toxprpl_statuses[
            toxprpl_get_status_index(tox,friend_number,userstatus)].id,
        NULL);
    g_free(buddy_key);
}

static void toxprpl_sync_friends(PurpleAccount *acct, Tox *tox)
{
    uint32_t i;

    uint32_t fl_len = tox_count_friendlist(tox);
    int *friendlist = g_malloc0(fl_len * sizeof(int));

    fl_len = tox_get_friendlist(tox, friendlist, fl_len);
    if (fl_len != 0)
    {
        purple_debug_info("toxprpl", "got %u friends\n", fl_len);
        GSList *buddies = purple_find_buddies(acct, NULL);
        GSList *iterator;
        for (i = 0; i < fl_len; i++)
        {
            iterator = buddies;
            int fnum = friendlist[i];
            uint8_t bin_id[TOX_CLIENT_ID_SIZE];
            if (tox_get_client_id(tox, fnum, bin_id) == 0)
            {
                gchar *str_id = toxprpl_tox_bin_id_to_string(bin_id);
                while (iterator != NULL)
                {
                    PurpleBuddy *buddy = iterator->data;
                    if (strcmp(buddy->name, str_id) == 0)
                    {
                        toxprpl_buddy_data *buddy_data =
                                    g_new0(toxprpl_buddy_data, 1);
                        buddy_data->tox_friendlist_number = fnum;
                        purple_buddy_set_protocol_data(buddy, buddy_data);
                        friendlist[i] = -1;
                    }
                    iterator = iterator->next;
                }
                g_free(str_id);
            }
        }

        iterator = buddies;
        // all left without buddy_data were not present in Tox and must be
        // removed
        while (iterator != NULL)
        {
            PurpleBuddy *buddy = iterator->data;
            toxprpl_buddy_data *buddy_data =
                purple_buddy_get_protocol_data(buddy);
            if (buddy_data == NULL)
            {
                purple_blist_remove_buddy(buddy);
            }
            iterator = iterator->next;
        }

        g_slist_free(buddies);
    }

    // all left in friendlist that were not reset are not yet in blist
    for (i = 0; i < fl_len; i++)
    {
        if (friendlist[i] != -1)
        {
            toxprpl_sync_add_buddy(acct, tox, friendlist[i]);
        }
    }

    g_free(friendlist);
}


static void toxprpl_login_after_setup(PurpleAccount *acct)
{
    purple_debug_info("toxprpl", "logging in...\n");

    PurpleConnection *gc = purple_account_get_connection(acct);

    Tox *tox = tox_new(0);
    if (tox == NULL)
    {
        purple_debug_info("toxprpl", "Fatal error, could not allocate memory "
                                     "for messenger!\n");
        return;

    }


    tox_callback_friend_message(tox, on_incoming_message, gc);
    tox_callback_name_change(tox, on_nick_change, gc);
    tox_callback_user_status(tox, on_status_change, gc);
    tox_callback_friend_request(tox, on_request, gc);
    tox_callback_connection_status(tox, on_connectionstatus, gc);
    tox_callback_friend_action(tox, on_friend_action, gc);

    purple_debug_info("toxprpl", "initialized tox callbacks\n");

    gc->flags |= PURPLE_CONNECTION_NO_FONTSIZE | PURPLE_CONNECTION_NO_URLDESC;
    gc->flags |= PURPLE_CONNECTION_NO_IMAGES | PURPLE_CONNECTION_NO_NEWLINES;

    purple_debug_info("toxprpl", "logging in %s\n", acct->username);

    const char *msg64 = purple_account_get_string(acct, "messenger", NULL);
    if ((msg64 != NULL) && (strlen(msg64) > 0))
    {
        purple_debug_info("toxprpl", "found existing account data\n");
        gsize out_len;
        guchar *msg_data = g_base64_decode(msg64, &out_len);
        if (msg_data && (out_len > 0))
        {
            if (tox_load(tox, (uint8_t *)msg_data, (uint32_t)out_len) != 0)
            {
                purple_debug_info("toxprpl", "Invalid account data\n");
                purple_account_set_string(acct, "messenger", NULL);
            }
            g_free(msg_data);
        }
    }

    purple_connection_update_progress(gc, _("Connecting"),
            0,   /* which connection step this is */
            2);  /* total number of steps */


    const char *key = purple_account_get_string(acct, "dht_server_key",
                                          DEFAULT_SERVER_KEY);
    /// \todo add limits check to make sure the user did not enter something
    /// invalid
    uint16_t port = (uint16_t)purple_account_get_int(acct, "dht_server_port",
                                   DEFAULT_SERVER_PORT);

    const char* ip = purple_account_get_string(acct, "dht_server",
                                               DEFAULT_SERVER_IP);

    unsigned char *bin_str = toxprpl_hex_string_to_data(key);

    purple_debug_info("toxprpl", "Will connect to %s:%d (%s)\n" ,
                      ip, port, key);

    if (tox_bootstrap_from_address(tox, ip, 0, htons(port), bin_str) == 0)
    {
        purple_connection_error_reason(gc,
                PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
                _("server invalid or not found"));
        g_free(bin_str);
        tox_kill(tox);
        return;
    }
    g_free(bin_str);

    toxprpl_sync_friends(acct, tox);

    toxprpl_plugin_data *plugin = g_new0(toxprpl_plugin_data, 1);

    plugin->tox = tox;
    plugin->tox_timer = purple_timeout_add(80, tox_messenger_loop, gc);
    purple_debug_info("toxprpl", "added messenger timer as %d\n",
                      plugin->tox_timer);
    plugin->connection_timer = purple_timeout_add_seconds(2,
                                                        tox_connection_check,
                                                        gc);
    purple_debug_info("toxprpl", "added connection timer as %d\n",
                      plugin->connection_timer);


    gchar *myid_help = "myid  print your tox id which you can give to "
                       "your friends";
    gchar *nick_help = "nick &lt;nickname&gt; set your nickname";

    plugin->myid_command_id = purple_cmd_register("myid", "",
            PURPLE_CMD_P_DEFAULT, PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT,
            TOXPRPL_ID, toxprpl_myid_cmd_cb, myid_help, gc);

    plugin->nick_command_id = purple_cmd_register("nick", "s",
            PURPLE_CMD_P_DEFAULT, PURPLE_CMD_FLAG_IM | PURPLE_CMD_FLAG_CHAT,
            TOXPRPL_ID, toxprpl_nick_cmd_cb, nick_help, gc);

    purple_connection_set_protocol_data(gc, plugin);
}

static void toxprpl_user_import(PurpleAccount *acct, const char *filename)
{
    purple_debug_info("toxprpl", "import user account: %s\n", filename);

    PurpleConnection *gc = purple_account_get_connection(acct);

    GStatBuf sb;
    if (g_stat(filename, &sb) != 0)
    {
        purple_notify_message(gc,
                PURPLE_NOTIFY_MSG_ERROR,
                _("Error"),
                _("Could not access account data file:"),
                filename,
                (PurpleNotifyCloseCallback)toxprpl_login,
                acct);
        return;
    }

    if ((sb.st_size == 0) || (sb.st_size > MAX_ACCOUNT_DATA_SIZE))
    {
        purple_notify_message(gc,
                PURPLE_NOTIFY_MSG_ERROR,
                _("Error"),
                _("Account data file seems to be invalid"),
                NULL,
                (PurpleNotifyCloseCallback)toxprpl_login,
                acct);
        return;
    }

    int fd = open(filename, O_RDONLY | O_BINARY);
    if (fd == -1)
    {
        purple_notify_message(gc,
                PURPLE_NOTIFY_MSG_ERROR,
                _("Error"),
                _("Could not open account data file:"),
                strerror(errno),
                (PurpleNotifyCloseCallback)toxprpl_login,
                acct);
        return;
    }

    guchar *account_data = g_malloc0(sb.st_size);
    guchar *p = account_data;
    size_t remaining = sb.st_size;
    while (remaining > 0)
    {
        ssize_t rb = read(fd, p, remaining);
        if (rb < 0)
        {
            purple_notify_message(gc,
                PURPLE_NOTIFY_MSG_ERROR,
                _("Error"),
                _("Could not read account data file:"),
                strerror(errno),
                (PurpleNotifyCloseCallback)toxprpl_login,
                acct);
            g_free(account_data);
            close(fd);
            return;
        }
        remaining = remaining - rb;
        p = p + rb;
    }

    gchar *msg64 = g_base64_encode(account_data, sb.st_size);
    purple_account_set_string(acct, "messenger", msg64);
    g_free(msg64);
    g_free(account_data);
    toxprpl_login(acct);
    close(fd);
}

static void toxprpl_user_ask_import(PurpleAccount *acct)
{
    purple_debug_info("toxprpl", "ask to import user account\n");
    PurpleConnection *gc = purple_account_get_connection(acct);

    purple_request_file(gc,
        _("Import existing Tox account data"),
        NULL,
        FALSE,
        G_CALLBACK(toxprpl_user_import),
        G_CALLBACK(toxprpl_login),
        acct,
        NULL,
        NULL,
        acct);
}

static void toxprpl_login(PurpleAccount *acct)
{
    PurpleConnection *gc = purple_account_get_connection(acct);

    // check if we need to run first time setup
    if (purple_account_get_string(acct, "messenger", NULL) == NULL)
    {
        purple_request_action(gc,
            _("Setup Tox account"),
            _("This appears to be your first login to the Tox network, "
              "would you like to start with a new user ID or would you "
              "like to import an existing one?"),
            _("Note: you can export / backup your account via the account "
              "actions menu."),
            PURPLE_DEFAULT_ACTION_NONE,
            acct, NULL, NULL,
            acct, // user data
            2,    // 2 choices
            _("Import existing Tox account"),
            G_CALLBACK(toxprpl_user_ask_import),
            _("Create new Tox account"),
            G_CALLBACK(toxprpl_login_after_setup));

        purple_notify_warning(gc,
                _("Development Version Warning"),
                _("This plugin is based on a development version of the "
                  "Tox library. There has not yet been an alpha nor a beta "
                  "release, the library is still 'work in progress' in "
                  "pre-alpha state.\n\n"
                  "This means that your conversations MAY NOT YET BE "
                  "SECURE!"), NULL);
    }
    else
    {
        toxprpl_login_after_setup(acct);
    }
}


static void toxprpl_close(PurpleConnection *gc)
{
    /* notify other toxprpl accounts */
    purple_debug_info("toxprpl", "Closing!\n");

    PurpleAccount *account = purple_connection_get_account(gc);
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    if (plugin == NULL)
    {
        return;
    }

    if (plugin->tox == NULL)
    {
        g_free(plugin);
        purple_connection_set_protocol_data(gc, NULL);
        return;
    }

    purple_debug_info("toxprpl", "removing timers %d and %d\n",
            plugin->tox_timer, plugin->connection_timer);
    purple_timeout_remove(plugin->tox_timer);
    purple_timeout_remove(plugin->connection_timer);

    purple_cmd_unregister(plugin->myid_command_id);
    purple_cmd_unregister(plugin->nick_command_id);

    uint32_t msg_size = tox_size(plugin->tox);
    if (msg_size > 0)
    {
        guchar *msg_data = g_malloc0(msg_size);
        tox_save(plugin->tox, (uint8_t *)msg_data);
        gchar *msg64 = g_base64_encode(msg_data, msg_size);
        purple_account_set_string(account, "messenger", msg64);
        g_free(msg64);
        g_free(msg_data);
    }
    else
    {
        purple_account_set_string(account, "messenger", "");
    }

    purple_debug_info("toxprpl", "shutting down\n");
    purple_connection_set_protocol_data(gc, NULL);
    tox_kill(plugin->tox);
    g_free(plugin);
}

/**
 * This PRPL function should return a positive value on success.
 * If the message is too big to be sent, return -E2BIG.  If
 * the account is not connected, return -ENOTCONN.  If the
 * PRPL is unable to send the message for another reason, return
 * some other negative value.  You can use one of the valid
 * errno values, or just big something.  If the message should
 * not be echoed to the conversation window, return 0.
 */
static int toxprpl_send_im(PurpleConnection *gc, const char *who,
        const char *message, PurpleMessageFlags flags)
{
    const char *from_username = gc->account->username;

    purple_debug_info("toxprpl", "sending message from %s to %s\n",
            from_username, who);

    int message_sent = -999;

    PurpleAccount *account = purple_connection_get_account(gc);
    PurpleBuddy *buddy = purple_find_buddy(account, who);
    if (buddy == NULL)
    {
        purple_debug_info("toxprpl", "Can't send message because buddy %s was not found\n", who);
        return message_sent;
    }
    toxprpl_buddy_data *buddy_data = purple_buddy_get_protocol_data(buddy);
    if (buddy_data == NULL)
    {
         purple_debug_info("toxprpl", "Can't send message because tox friend number is unknown\n");
        return message_sent;
    }
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    char *no_html = purple_markup_strip_html(message);

    if (purple_message_meify(no_html, -1))
    {
        if (tox_send_action(plugin->tox, buddy_data->tox_friendlist_number,
                                    (uint8_t *)no_html, strlen(message)+1) == 1)
        {
            message_sent = 1;
        }
    }
    else
    {
        if (tox_send_message(plugin->tox, buddy_data->tox_friendlist_number,
                                   (uint8_t *)no_html, strlen(message)+1) != 0)
        {
            message_sent = 1;
        }
    }
    if (no_html)
    {
        free(no_html);
    }
    return message_sent;
}

static int toxprpl_tox_add_friend(Tox *tox, PurpleConnection *gc,
                                 const char *buddy_key,
                                 gboolean sendrequest,
                                 const char *message)
{
    unsigned char *bin_key = toxprpl_hex_string_to_data(buddy_key);
    int ret;

    if (sendrequest == TRUE)
    {
        if ((message == NULL) || (strlen(message) == 0))
        {
            message = DEFAULT_REQUEST_MESSAGE;
        }
        ret = tox_add_friend(tox, bin_key, (uint8_t *)message,
                            (uint16_t)strlen(message) + 1);
    }
    else
    {
        ret = tox_add_friend_norequest(tox, bin_key);
    }

    g_free(bin_key);
    const char *msg;
    switch (ret)
    {
        case TOX_FAERR_TOOLONG:
            msg = "Message too long";
            break;
        case TOX_FAERR_NOMESSAGE:
            msg = "Missing request message";
            break;
        case TOX_FAERR_OWNKEY:
            msg = "You're trying to add yourself as a friend";
            break;
        case TOX_FAERR_ALREADYSENT:
            msg = "Friend request already sent";
            break;
        case TOX_FAERR_BADCHECKSUM:
            msg = "Can't add friend: bad checksum in ID";
            break;
        case TOX_FAERR_SETNEWNOSPAM:
            msg = "Can't add friend: wrong nospam ID";
            break;
        case TOX_FAERR_NOMEM:
            msg = "Could not allocate memory for friendlist";
            break;
        case TOX_FAERR_UNKNOWN:
            msg = "Error adding friend";
            break;
        default:
            break;
    }

    if (ret < 0)
    {
        purple_notify_error(gc, _("Error"), msg, NULL);
    }
    else
    {
        purple_debug_info("toxprpl", "Friend %s added as %d\n", buddy_key, ret);
    }

    return ret;
}

static void toxprpl_do_not_add_to_buddylist(toxprpl_accept_friend_data *data)
{
    g_free(data->buddy_key);
    g_free(data);
}

static void toxprpl_add_to_buddylist(toxprpl_accept_friend_data *data)
{
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(data->gc);

    int ret = toxprpl_tox_add_friend(plugin->tox, data->gc, data->buddy_key,
                                    FALSE, NULL);
    if (ret < 0)
    {
        g_free(data->buddy_key);
        g_free(data);
        // error dialogs handled in toxprpl_tox_add_friend()
        return;
    }

    PurpleAccount *account = purple_connection_get_account(data->gc);

    uint8_t alias[TOX_MAX_NAME_LENGTH];

    PurpleBuddy *buddy;
    if ((tox_get_name(plugin->tox, ret, alias) == 0) &&
        (strlen((const char *)alias) > 0))
    {
        purple_debug_info("toxprpl", "Got friend alias %s\n", alias);
        buddy = purple_buddy_new(account, data->buddy_key, (const char*)alias);
    }
    else
    {
        purple_debug_info("toxprpl", "Adding [%s]\n", data->buddy_key);
        buddy = purple_buddy_new(account, data->buddy_key, NULL);
    }

    toxprpl_buddy_data *buddy_data = g_new0(toxprpl_buddy_data, 1);
    buddy_data->tox_friendlist_number = ret;
    purple_buddy_set_protocol_data(buddy, buddy_data);
    purple_blist_add_buddy(buddy, NULL, NULL, NULL);
    TOX_USERSTATUS userstatus = tox_get_user_status(plugin->tox, ret);
    purple_debug_info("toxprpl", "Friend %s has status %d\n",
            data->buddy_key, userstatus);
    purple_prpl_got_user_status(account, data->buddy_key,
        toxprpl_statuses[toxprpl_get_status_index(plugin->tox,ret,userstatus)].id,
        NULL);

    g_free(data->buddy_key);
    g_free(data);
}

static void toxprpl_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
        PurpleGroup *group, const char *msg)
{
    purple_debug_info("toxprpl", "adding %s to buddy list\n", buddy->name);

    buddy->name = g_strstrip(buddy->name);
    if (strlen(buddy->name) != (TOX_FRIEND_ADDRESS_SIZE * 2))
    {
        purple_notify_error(gc, _("Error"),
                            _("Invalid buddy ID given (must be 76 characters "
                              "long)"), NULL);
        purple_blist_remove_buddy(buddy);
        return;
    }

    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    int ret = toxprpl_tox_add_friend(plugin->tox, gc, buddy->name, TRUE, msg);
    if (ret < 0)
    {
        purple_debug_info("toxprpl", "adding buddy %s failed (%d)\n",
                          buddy->name, ret);
        purple_blist_remove_buddy(buddy);
        return;
    }

    gchar *cut = g_ascii_strdown(buddy->name, TOX_CLIENT_ID_SIZE * 2 + 1);
    cut[TOX_CLIENT_ID_SIZE * 2] = '\0';
    purple_debug_info("toxprpl", "converted %s to %s\n", buddy->name, cut);
    purple_blist_rename_buddy(buddy, cut);
    g_free(cut);
    // buddy data will be added by the query_buddy_info function
    toxprpl_query_buddy_info((gpointer)buddy, (gpointer)gc);
}

static void toxprpl_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
        PurpleGroup *group)
{
    purple_debug_info("toxprpl", "removing buddy %s\n", buddy->name);
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    toxprpl_buddy_data *buddy_data = purple_buddy_get_protocol_data(buddy);
    if (buddy_data != NULL)
    {
        purple_debug_info("toxprpl", "removing tox friend #%d\n", buddy_data->tox_friendlist_number);
        tox_del_friend(plugin->tox, buddy_data->tox_friendlist_number);
    }
}

static void toxprpl_show_id_dialog_closed(gchar *id)
{
    g_free(id);
}

static void toxprpl_action_show_id_dialog(PurplePluginAction *action)
{
    PurpleConnection *gc = (PurpleConnection*)action->context;

    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);

    uint8_t bin_id[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(plugin->tox, bin_id);
    gchar *id = toxprpl_tox_friend_id_to_string(bin_id);

    purple_notify_message(gc,
            PURPLE_NOTIFY_MSG_INFO,
            _("Account ID"),
            _("If someone wants to add you, give them this ID:"),
            id,
            (PurpleNotifyCloseCallback)toxprpl_show_id_dialog_closed,
            id);
}

static void toxprpl_action_set_nick_dialog(PurplePluginAction *action)
{
    PurpleConnection *gc = (PurpleConnection*)action->context;
    PurpleAccount *account = purple_connection_get_account(gc);

    purple_request_input(gc, _("Set nickname"),
                         _("New nickname:"),
                         NULL,
                         purple_account_get_string(account, "nickname", ""),
                         FALSE, FALSE, NULL,
                         _("_Set"), G_CALLBACK(toxprpl_set_nick_action),
                         _("_Cancel"), NULL,
                         account, account->username, NULL,
                         gc);
}


static void toxprpl_user_export(PurpleConnection *gc, const char *filename)
{
    purple_debug_info("toxprpl", "export account to %s\n", filename);

    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    if (plugin == NULL)
    {
        return;
    }

    if (plugin->tox == NULL)
    {
        return;
    }

    PurpleAccount *account = purple_connection_get_account(gc);

    uint32_t msg_size = tox_size(plugin->tox);
    if (msg_size > 0)
    {
        uint8_t *account_data = g_malloc0(msg_size);
        tox_save(plugin->tox, account_data);
        guchar *p = account_data;

        int fd = open(filename, O_RDWR | O_CREAT | O_BINARY, S_IRUSR | S_IWUSR);
        if (fd == -1)
        {
            g_free(account_data);
            purple_notify_message(gc,
                    PURPLE_NOTIFY_MSG_ERROR,
                    _("Error"),
                    _("Could not save account data file:"),
                    strerror(errno),
                    NULL, NULL);
            return;
        }

        size_t remaining = (size_t)msg_size;
        while (remaining > 0)
        {
            ssize_t wb = write(fd, p, remaining);
            if (wb < 0)
            {
                purple_notify_message(gc,
                    PURPLE_NOTIFY_MSG_ERROR,
                    _("Error"),
                    _("Could not save account data file:"),
                    strerror(errno),
                    (PurpleNotifyCloseCallback)toxprpl_login,
                    account);
                g_free(account_data);
                close(fd);
                return;
            }
            remaining = remaining - wb;
            p = p + wb;
        }

        g_free(account_data);
        close(fd);
    }
}

static void toxprpl_export_account_dialog(PurplePluginAction *action)
{
    purple_debug_info("toxprpl", "ask to export account\n");

    PurpleConnection *gc = (PurpleConnection*)action->context;
    PurpleAccount *account = purple_connection_get_account(gc);
    toxprpl_plugin_data *plugin = purple_connection_get_protocol_data(gc);
    if (plugin == NULL)
    {
        return;
    }

    if (plugin->tox == NULL)
    {
        return;
    }

    uint8_t bin_id[TOX_FRIEND_ADDRESS_SIZE];
    tox_get_address(plugin->tox, bin_id);
    gchar *id = toxprpl_tox_friend_id_to_string(bin_id);
    strcpy(id+TOX_CLIENT_ID_SIZE, ".tox\0"); // insert extension instead of nospam

    purple_request_file(gc,
        _("Export existing Tox account data"),
        id,
        TRUE,
        G_CALLBACK(toxprpl_user_export),
        NULL,
        account,
        NULL,
        NULL,
        gc);
    g_free(id);
}

static GList *toxprpl_account_actions(PurplePlugin *plugin, gpointer context)
{
    purple_debug_info("toxprpl", "setting up account actions\n");

    GList *actions = NULL;
    PurplePluginAction *action;

    action = purple_plugin_action_new(_("Show my id..."),
             toxprpl_action_show_id_dialog);
    actions = g_list_append(actions, action);

    action = purple_plugin_action_new(_("Set nickname..."),
             toxprpl_action_set_nick_dialog);
    actions = g_list_append(actions, action);

    action = purple_plugin_action_new(_("Export account data..."),
            toxprpl_export_account_dialog);
    actions = g_list_append(actions, action);
    return actions;
}

static void toxprpl_free_buddy(PurpleBuddy *buddy)
{
    if (buddy->proto_data)
    {
        toxprpl_buddy_data *buddy_data = buddy->proto_data;
        g_free(buddy_data);
    }
}

static gboolean toxprpl_offline_message(const PurpleBuddy *buddy)
{
    return FALSE;
}


static PurplePluginProtocolInfo prpl_info =
{
    OPT_PROTO_NO_PASSWORD | OPT_PROTO_REGISTER_NOSCREENNAME | OPT_PROTO_INVITE_MESSAGE,  /* options */
    NULL,                               /* user_splits, initialized in toxprpl_init() */
    NULL,                               /* protocol_options, initialized in toxprpl_init() */
    NO_BUDDY_ICONS,                     /* icon spec */
    toxprpl_list_icon,                  /* list_icon */
    NULL,                               /* list_emblem */
    NULL,                               /* status_text */
    NULL,                               /* tooltip_text */
    toxprpl_status_types,               /* status_types */
    NULL,                               /* blist_node_menu */
    NULL,                               /* chat_info */
    NULL,                               /* chat_info_defaults */
    toxprpl_login,                      /* login */
    toxprpl_close,                      /* close */
    toxprpl_send_im,                    /* send_im */
    NULL,                               /* set_info */
    NULL,                               /* send_typing */
    NULL,                               /* get_info */
    toxprpl_set_status,                 /* set_status */
    NULL,                               /* set_idle */
    NULL,                               /* change_passwd */
    NULL,                               /* add_buddy */
    NULL,                               /* add_buddies */
    toxprpl_remove_buddy,               /* remove_buddy */
    NULL,                               /* remove_buddies */
    NULL,                               /* add_permit */
    NULL,                               /* add_deny */
    NULL,                               /* rem_permit */
    NULL,                               /* rem_deny */
    NULL,                               /* set_permit_deny */
    NULL,                               /* join_chat */
    NULL,                               /* reject_chat */
    NULL,                               /* get_chat_name */
    NULL,                               /* chat_invite */
    NULL,                               /* chat_leave */
    NULL,                               /* chat_whisper */
    NULL,                               /* chat_send */
    NULL,                               /* keepalive */
    NULL,                               /* register_user */
    NULL,                               /* get_cb_info */
    NULL,                               /* get_cb_away */
    NULL,                               /* alias_buddy */
    NULL,                               /* group_buddy */
    NULL,                               /* rename_group */
    toxprpl_free_buddy,                 /* buddy_free */
    NULL,                               /* convo_closed */
    NULL,                               /* normalize */
    NULL,                               /* set_buddy_icon */
    NULL,                               /* remove_group */
    NULL,                               /* get_cb_real_name */
    NULL,                               /* set_chat_topic */
    NULL,                               /* find_blist_chat */
    NULL,                               /* roomlist_get_list */
    NULL,                               /* roomlist_cancel */
    NULL,                               /* roomlist_expand_category */
    NULL,                               /* can_receive_file */
    NULL,                               /* send_file */
    NULL,                               /* new_xfer */
    toxprpl_offline_message,            /* offline_message */
    NULL,                               /* whiteboard_prpl_ops */
    NULL,                               /* send_raw */
    NULL,                               /* roomlist_room_serialize */
    NULL,                               /* unregister_user */
    NULL,                               /* send_attention */
    NULL,                               /* get_attention_types */
    sizeof(PurplePluginProtocolInfo),   /* struct_size */
    NULL,                               /* get_account_text_table */
    NULL,                               /* initiate_media */
    NULL,                               /* get_media_caps */
    NULL,                               /* get_moods */
    NULL,                               /* set_public_alias */
    NULL,                               /* get_public_alias */
    toxprpl_add_buddy,                  /* add_buddy_with_invite */
    NULL                                /* add_buddies_with_invite */
};

static void toxprpl_init(PurplePlugin *plugin)
{
    purple_debug_info("toxprpl", "starting up\n");

    PurpleAccountOption *option = purple_account_option_string_new(
        _("Nickname"), "nickname", "");
    prpl_info.protocol_options = g_list_append(NULL, option);

    option = purple_account_option_string_new(
        _("Server"), "dht_server", DEFAULT_SERVER_IP);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options,
                                               option);

    option = purple_account_option_int_new(_("Port"), "dht_server_port",
            DEFAULT_SERVER_PORT);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options,
                                               option);

    option = purple_account_option_string_new(_("Server key"),
        "dht_server_key", DEFAULT_SERVER_KEY);
    prpl_info.protocol_options = g_list_append(prpl_info.protocol_options,
                                               option);
    purple_debug_info("toxprpl", "initialization complete\n");
}

static PurplePluginInfo info =
{
    PURPLE_PLUGIN_MAGIC,                                /* magic */
    PURPLE_MAJOR_VERSION,                               /* major_version */
    PURPLE_MINOR_VERSION,                               /* minor_version */
    PURPLE_PLUGIN_PROTOCOL,                             /* type */
    NULL,                                               /* ui_requirement */
    0,                                                  /* flags */
    NULL,                                               /* dependencies */
    PURPLE_PRIORITY_DEFAULT,                            /* priority */
    TOXPRPL_ID,                                         /* id */
    "Tox",                                              /* name */
    VERSION,                                            /* version */
    "Tox Protocol Plugin",                              /* summary */
    "Tox Protocol Plugin http://tox.im/",               /* description */
    "Sergey 'Jin' Bostandzhyan",                        /* author */
    PACKAGE_URL,                                        /* homepage */
    NULL,                                               /* load */
    NULL,                                               /* unload */
    NULL,                                               /* destroy */
    NULL,                                               /* ui_info */
    &prpl_info,                                         /* extra_info */
    NULL,                                               /* prefs_info */
    toxprpl_account_actions,                            /* actions */
    NULL,                                               /* padding... */
    NULL,
    NULL,
    NULL,
};

PURPLE_INIT_PLUGIN(tox, toxprpl_init, info);
