AC_INIT([corkscrew], [2.0])
AC_CONFIG_SRCDIR([corkscrew.c])
AC_CONFIG_HEADERS([config.h:config.in])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SEARCH_LIBS([socket], [socket xnet])
AC_SEARCH_LIBS([getaddrinfo], [nsl xnet])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_CHECK_HEADERS([sys/filio.h])
AC_CHECK_FUNCS([poll getaddrinfo clock_gettime explicit_bzero])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
