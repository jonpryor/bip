AC_PREREQ([2.69])
AC_INIT([Bip IRC Proxy],[0.9.0-rc3-git],[http://bip.milkypond.org/projects/bip/activity],[bip],[http://bip.milkypond.org/])
AM_INIT_AUTOMAKE([foreign -Wall -Werror])
AM_MAINTAINER_MODE

AC_CONFIG_HEADERS([src/config.h])

# Checks for programs
AC_PROG_CC
AM_PROG_AR
AC_PROG_RANLIB
AC_PROG_INSTALL
AM_PROG_LEX
AC_PROG_YACC

# Deal with parameters
AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Enable debug build]))
AC_ARG_WITH([openssl], AS_HELP_STRING([--without-openssl],
  [Disable SSL using OpenSSL]))
AC_ARG_ENABLE([oidentd], AS_HELP_STRING([--enable-oidentd],
  [Enable oidentd support (bip overwrites ~/.oidentd.conf with this on!)]))
AC_ARG_ENABLE([pie], AS_HELP_STRING([--disable-pie],
  [Do not build a position independent executable]))
AC_ARG_ENABLE([tests], AS_HELP_STRING([--enable-tests], [Build tests]))

AM_CONDITIONAL(DEBUG, test x$enable_debug = xyes)
AS_IF([test "x$enable_debug" = "xyes"], [
	AC_CHECK_FUNC(backtrace_symbols_fd, [
		AC_DEFINE(HAVE_BACKTRACE, [], [Use glibc backtrace on fatal()])
		LDFLAGS="-rdynamic $LDFLAGS"
		backtrace="(with backtrace)"
	])
], [
	enable_debug=no
])

AM_CONDITIONAL(OIDENTD, test x$enable_identd = xyes)
AS_IF([test "x$enable_oidentd" = "xyes"], [
	AC_DEFINE([HAVE_OIDENTD], [], [Have bip edit ~/.oidentd.conf])
], [
    	enable_oidentd=no
])

AS_IF([test "x$with_openssl" != "xno"], [
	AC_CHECK_LIB(crypto, CRYPTO_new_ex_data, [], [
		AC_MSG_ERROR([library 'crypto' is required for OpenSSL support])
		with_openssl=no
	], -lcrypto)
	AC_CHECK_LIB(ssl, SSL_read, [], [
		AC_MSG_ERROR([library 'ssl' is required for OpenSSL support])
		with_openssl=no
	], -lssl)
], [
    	with_openssl=no
])

AS_IF([test "x$enable_pie" != "xno"], [
	AC_CACHE_CHECK([whether $CC accepts PIE flags], [ap_cv_cc_pie], [
		save_CFLAGS=$CFLAGS 
		save_LDFLAGS=$LDFLAGS 
		CFLAGS="$CFLAGS -fPIE" 
		LDFLAGS="$LDFLAGS -pie" 
		AC_RUN_IFELSE([AC_LANG_SOURCE([[static int foo[30000]; int main () { return 0; }]])],
			[ap_cv_cc_pie=yes],
			[ap_cv_cc_pie=no],
			[ap_cv_cc_pie=yes]
		)
		CFLAGS=$save_CFLAGS
		LDFLAGS=$save_LDFLAGS
	])
	if test "$ap_cv_cc_pie" = "yes"; then
		CFLAGS="$CFLAGS -fPIE"
		LDFLAGS="$LDFLAGS -pie"
		enable_pie=yes
	fi
])

AS_IF([test "x$enable_tests" != "xno"], [
       PKG_CHECK_MODULES([CHECK], [check >= 0.9.6])
])


AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT

AS_IF([test "x$with_openssl" != "xno"], [
echo OPENSSL: yes
])
echo DEBUG: $enable_debug $backtrace
echo OIDENTD: $enable_oidentd
echo PIE: $enable_pie
AS_IF([test "x$enable_tests" != "xno"], [
echo TESTS: $enable_tests
])
