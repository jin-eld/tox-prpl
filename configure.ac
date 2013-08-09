#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.66])
AC_INIT([tox-prlp], [0.0.0], [jin@mediatomb.cc],[],
        [https://github.com/jin-eld/tox-prpl/])
AC_CONFIG_SRCDIR([src/toxprpl.c])
AC_CONFIG_HEADERS([autoconfig.h])
AM_INIT_AUTOMAKE([1.10 -Wall])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])
AC_CONFIG_MACRO_DIR([m4])

if test "x${prefix}" = "xNONE"; then
    prefix="${ac_default_prefix}"
fi

DEPSEARCH=
AC_ARG_WITH(dependency-search,
    AC_HELP_STRING([--with-dependency-search=DIR],
                   [search for dependencies in DIR, i.e. look for libraries in
                    DIR/lib and for headers in DIR/include]),
    [
        DEPSEARCH="$withval"
    ]
)

if test -n "$DEPSEARCH"; then
    CFLAGS="$CFLAGS -I$DEPSEARCH/include"
    CPPFLAGS="$CPPFLAGS -I$DEPSEARCH/include"
    LDFLAGS="$LDFLAGS -L$DEPSEARCH/lib"
    export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$DEPSEARCH/lib/pkgconfig
fi

AC_ARG_WITH(libtoxcore-headers,
        AC_HELP_STRING([--with-libtoxcore-headers=DIR],
                       [search for libtoxcore header files in DIR]),
        [
            LIBTOXCORE_SEARCH_HEADERS="$withval"
            AC_MSG_NOTICE([Will search for libtoxcore header files in $withval])
        ]
)

AC_ARG_WITH(libtoxcore-libs,
        AC_HELP_STRING([--with-libtoxcore-libs=DIR],
                       [search for libtoxcore libraries in DIR]),
        [
            LIBTOXCORE_SEARCH_LIBS="$withval"
            AC_MSG_NOTICE([Will search for libtoxcore libraries in $withval])
        ]
)

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Checks for libraries.
AC_STRUCT_TM
AC_CHECK_SIZEOF(time_t, [],[
#include <stdio.h>
#include <time.h>])

LIBTOXCORE_LIBS=
LIBTOXCORE_LDFLAGS=
LDFLAGS_SAVE="$LDFLAGS"
if test -n "$LIBTOXCORE_SEARCH_LIBS"; then
    LDFLAGS="-L$LIBTOXCORE_SEARCH_LIBS"
    AC_CHECK_LIB(toxcore, getclient_id,
        [
            LIBTOXCORE_LDFLAGS="-L$LIBTOXCORE_SEARCH_LIBS"
            LIBTOXCORE_LIBS="-ltoxcore"
        ],
        [
            AC_MSG_ERROR([required library libtoxcore was not found in requested location $LIBTOXCORE_SEARCH_LIBS])
        ]
    )
else
    AC_CHECK_LIB(toxcore, getclient_id,
        [],
        [
            AC_MSG_ERROR([required library libtoxcore was not found on the system, please check http://tox.im/])
        ]
    )
fi

LDFLAGS="$LDFLAGS_SAVE"
AC_SUBST(LIBTOXCORE_LIBS)
AC_SUBST(LIBTOXCORE_LDFLAGS)

# Checks for header files.
AC_CHECK_HEADERS([string.h])

LIBTOXCORE_CFLAGS=
CFLAGS_SAVE="$CFLAGS"
CPPFLAGS_SAVE="$CPPFLAGS"
if test -n "$LIBTOXCORE_SEARCH_HEADERS"; then
    CFLAGS="-I$LIBTOXCORE_SEARCH_HEADERS"
    CPPFLAGS="-I$LIBTOXCORE_SEARCH_HEADERS"
    AC_CHECK_HEADER(tox/Messenger.h,
        [
            LIBTOXCORE_CFLAGS="-I$LIBTOXCORE_SEARCH_HEADERS"
        ],
        [
            AC_MSG_ERROR([header files for required library libtoxcore was not found in requested location $LIBTOXCORE_SEARCH_HEADERS])
        ]
    )
else
    AC_CHECK_HEADER(tox/Messenger.h,
        [],
        [
            AC_MSG_ERROR([header files for required library libtoxcore was not found on your systm])
        ]
    )
fi
CFLAGS="$CFLAGS_SAVE"
CPPFLAGS="$CPPFLAGS_SAVE"
AC_SUBST(LIBTOXCORE_CFLAGS)

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

PKG_CHECK_MODULES(PURPLE, [purple >= 2.7.0])

PKG_CHECK_MODULES(GLIB, [glib-2.0])
AC_CONFIG_FILES([Makefile
                 build/Makefile
                ])
AC_OUTPUT
