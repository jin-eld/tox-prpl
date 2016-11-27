SUBDIRS=build pixmaps

ACLOCAL_AMFLAGS = -I m4

BUILT_SOURCES = $(top_builddir)/nsis/tox-prpl.nsi
CLEANFILES = $(top_builddir)/nsis/tox-prpl.nsi
EXTRA_DIST = nsis/tox.ico README

if HAVE_NSIS
nsis-installer: $(BUILT_SOURCES) autoconfig.h
	$(MAKE) $(AM_MAKEFLAGS) all-recursive
	$(MAKE) $(AM_MAKEFLAGS) install-recursive
	$(MAKENSIS) $(top_builddir)/nsis/tox-prpl.nsi
else
nsis-installer:
	@echo "makensis is not available, can't generate installer"
endif

clean-local: clean-nsis-installer

clean-nsis-installer:
	-rm -f  $(top_builddir)/build/tox-prpl-pidgin-$(VERSION)$(EXEEXT)

.PHONY: nsis-installer clean-nsis-installer
