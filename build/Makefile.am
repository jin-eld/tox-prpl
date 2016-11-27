TOXSOURCES = ../src/toxprpl.c

libtox_la_LDFLAGS = $(EXTRA_LT_LDFLAGS)

# todo: check and pass value from configure
PURPLE_MAJOR_VERSION = "2"

pkgdir = $(libdir)/purple-$(PURPLE_MAJOR_VERSION)

pkg_LTLIBRARIES    = libtox.la
libtox_la_SOURCES = $(TOXSOURCES)
libtox_la_CFLAGS = 	-I.. \
					-I../src \
					$(GLIB_CFLAGS) \
					$(PURPLE_CFLAGS) \
					$(LIBTOXCORE_CFLAGS)

libtox_la_LIBADD  =	$(GLIB_LIBS) \
					$(PURPLE_LIBS) \
					$(LIBTOXCORE_LIBS)

