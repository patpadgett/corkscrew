AC_INIT(corkscrew, 2.0)
AC_CONFIG_SRCDIR(corkscrew.c)
AM_CONFIG_HEADER(config.h:config.in)
AM_INIT_AUTOMAKE

AC_PROG_CC
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S

AC_ARG_ENABLE([ssl], AS_HELP_STRING([--enable-ssl], [Enable SSL connections to the proxy server]))

AC_CANONICAL_HOST
case "$host_os" in
  solaris*)
    AC_CHECK_LIB(xnet, socket)
    AC_CHECK_LIB(xnet, gethostbyname)
    AC_CHECK_LIB(xnet, inet_addr)
    AC_CHECK_LIB(xnet, connect)
    AC_CHECK_HEADERS(sys/filio.h)
  ;;
esac

AC_HEADER_STDC
AC_HEADER_TIME
AC_CHECK_FUNCS(select socket strerror)

dnl check for working const (hpux)
AC_C_CONST

AM_CONDITIONAL([SSL], [test "x$enable_ssl" = "xyes"])
AS_IF([test "x$enable_ssl" = "xyes"], [PKG_CHECK_MODULES([SSL], [openssl >= 1.0.0])])

AC_CHECK_TYPE([struct addrinfo], [have_addrinfo=yes], [], [[#include <netdb.h>]])
AM_CONDITIONAL([IPV6], [test "x$have_addrinfo" = "xyes"])

AC_CHECK_MEMBER([struct hostent.h_addr],
		[AC_DEFINE([HAVE_H_ADDR], [1],
			   [Define to 1 if struct hostent contains the h_addr member.])],
		[], [[#include <netdb.h>]])

AC_OUTPUT(Makefile)
