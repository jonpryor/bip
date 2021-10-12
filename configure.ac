AC_PREREQ([2.69])
AC_INIT([Bip IRC Proxy],[0.9.2-git],[http://bip.milkypond.org/projects/bip/activity],[bip],[http://bip.milkypond.org/])
AM_INIT_AUTOMAKE([foreign subdir-objects -Wall -Werror])
AM_MAINTAINER_MODE

AC_CONFIG_HEADERS([src/config.h])

# Checks for programs
AC_PROG_CC
AM_PROG_AR
AC_PROG_RANLIB
AC_PROG_INSTALL
AM_PROG_LEX
AC_PROG_YACC
m4_ifndef([PKG_PROG_PKG_CONFIG], [m4_fatal([Please install pkg-config.])])
PKG_PROG_PKG_CONFIG

PKG_CHECK_MODULES(OPENSSL, [libssl >= 0.9.8 libcrypto >= 0.9.8], [
			    with_openssl=yes
			    AC_DEFINE([HAVE_LIBSSL], [1],
						       [Build SSL support])
			    ], [ with_openssl=no ])

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

PKG_CHECK_MODULES([CHECK], [check >= 0.9.6], [enable_tests=yes], [enable_tests=no])
AM_CONDITIONAL([COND_WANT_TESTS], [test "$enable_tests" = yes])

AC_CHECK_FUNC(backtrace_symbols_fd, [
        AC_DEFINE(HAVE_BACKTRACE, [], [Use glibc backtrace on fatal()])
        LDFLAGS="-rdynamic $LDFLAGS"
        backtrace="(with backtrace)"
])


AC_CONFIG_FILES([Makefile src/Makefile tests/Makefile])
AC_OUTPUT

echo OPENSSL: $with_openssl
echo PIE: $enable_pie
echo TESTS: $enable_tests
