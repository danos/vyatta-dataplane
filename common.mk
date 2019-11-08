AM_CPPFLAGS = \
	-DVYATTA_SYSCONF_DIR='"$(sysconfdir)/vyatta"' \
	-DVYATTA_DATA_DIR='"$(datadir)/vyatta"' \
	-DPKGLIB_DIR='"$(pkglibdir)"' \
	-include build_config.h # Details of the build configuration
