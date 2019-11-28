AM_CPPFLAGS                = -I./include \
				-I$(DEV_HOME)/include \
				-I$(INSTALL_HOME)/pfsdk/include \
				-I$(INSTALL_HOME)/pfms/include \
				$(UNIMRCP_PLUGIN_INCLUDES)

plugin_LTLIBRARIES         = uasrrecog.la

uasrrecog_la_SOURCES       = src/uasr_recog_engine.cpp
uasrrecog_la_LDFLAGS       = $(UNIMRCP_PLUGIN_OPTS) \
				-L$(DEV_HOME)/lib -L$(INSTALL_HOME)/pfsdk/lib -L$(INSTALL_HOME)/pfms/lib -lpfmsc -lpfsdk

install-data-local:
	test -d $(DESTDIR)$(sysconfdir) || $(MAKE) def-conf
	test -f $(DESTDIR)$(sysconfdir)/uasrrecog.xml || $(INSTALL) -m 644 conf/uasrrecog.xml $(DESTDIR)$(sysconfdir)

include $(top_srcdir)/build/rules/uniplugin.am
