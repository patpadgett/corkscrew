AC_INIT([corkscrew], [3.0])
AC_CONFIG_SRCDIR([corkscrew.c])
AC_CONFIG_HEADERS([config.h:config.in])
AM_INIT_AUTOMAKE([foreign])
AC_PROG_CC
AC_USE_SYSTEM_EXTENSIONS
AC_SEARCH_LIBS([socket], [socket xnet])
AC_SEARCH_LIBS([getaddrinfo], [nsl xnet])
AC_SEARCH_LIBS([clock_gettime], [rt])
AC_CHECK_FUNCS([poll getaddrinfo clock_gettime], [],
    [AC_MSG_ERROR([required POSIX function missing])])
AC_CHECK_FUNCS([explicit_bzero])

dnl Python is required only for the regression suite, not for building.
AC_PATH_PROG([PYTHON], [python3], [no])
AM_CONDITIONAL([HAVE_PYTHON], [test "x$PYTHON" != "xno"])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
