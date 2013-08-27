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

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h string.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# pkg-config checks

PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(PURPLE, [purple >= 2.7.0])

PKG_CHECK_MODULES(GLIB, [glib-2.0])

PKG_CHECK_MODULES(LIBTOXCORE, [libtoxcore])


EXTRA_LT_LDFLAGS="-avoid-version"

WIN32="no"
AC_CANONICAL_HOST
case $host_os in
    *mingw*)
        WIN32="yes"
        EXTRA_LT_LDFLAGS="$EXTRA_LT_LDFLAGS -module -no-undefined"
    ;;
    *darwin* | *rhapsody* | *macosx*)
    ;;
    *)
        EXTRA_LT_LDFLAGS="$EXTRA_LT_LDFLAGS -module"
    ;;
esac

if test "x$WIN32" = "xyes"; then
    AC_CHECK_LIB(ws2_32, main,
        [
            WINSOCK2_LIBS="-lws2_32"
            AC_SUBST(WINSOCK2_LIBS)
        ],
        [
            AC_MSG_ERROR([required library was not found on the system, please c
heck your MinGW installation])
        ])

   AC_CHECK_HEADERS([winsock2.h ws2tcpip.h],
       [],
       [
           AC_MSG_ERROR([required header was not found on the system, please check your MinGW installation])
       ])
   AC_DEFINE([_WIN32_WINNT], [0x501],
             [enable getaddrinfo/freeaddrinfo for XP and higher])
fi


AC_CONFIG_FILES([Makefile
                 build/Makefile
                 pixmaps/Makefile
                ])
AC_OUTPUT
