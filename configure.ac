m4_pattern_allow([^AM_])
m4_pattern_allow([^AC_])

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

dnl PKG_PREREQ(MIN-VERSION)
dnl -----------------------
dnl Since: 0.29
dnl
dnl Verify that the version of the pkg-config macros are at least
dnl MIN-VERSION. Unlike PKG_PROG_PKG_CONFIG, which checks the user's
dnl installed version of pkg-config, this checks the developer's version
dnl of pkg.m4 when generating configure.
dnl
dnl To ensure that this macro is defined, also add:
dnl m4_ifndef([PKG_PREREQ],
dnl     [m4_fatal([must install pkg-config 0.29 or later before running autoconf/autogen])])
dnl
dnl See the "Since" comment for each macro you use to see what version
dnl of the macros you require.
m4_defun([PKG_PREREQ],
[m4_define([PKG_MACROS_VERSION], [0.29.1])
m4_if(m4_version_compare(PKG_MACROS_VERSION, [$1]), -1,
	[m4_fatal([pkg.m4 version $1 or higher is required but ]PKG_MACROS_VERSION[ found])])
])dnl PKG_PREREQ

dnl PKG_PROG_PKG_CONFIG([MIN-VERSION])
dnl ----------------------------------
dnl Since: 0.16
dnl
dnl Search for the pkg-config tool and set the PKG_CONFIG variable to
dnl first found in the path. Checks that the version of pkg-config found
dnl is at least MIN-VERSION. If MIN-VERSION is not specified, 0.9.0 is
dnl used since that's the first version where most current features of
dnl pkg-config existed.
AC_DEFUN([PKG_PROG_PKG_CONFIG],
[m4_pattern_forbid([^_?PKG_[A-Z_]+$])
m4_pattern_allow([^PKG_CONFIG(_(PATH|LIBDIR|SYSROOT_DIR|ALLOW_SYSTEM_(CFLAGS|LIBS)))?$])
m4_pattern_allow([^PKG_CONFIG_(DISABLE_UNINSTALLED|TOP_BUILD_DIR|DEBUG_SPEW)$])
AC_ARG_VAR([PKG_CONFIG], [path to pkg-config utility])
AC_ARG_VAR([PKG_CONFIG_PATH], [directories to add to pkg-config's search path])
AC_ARG_VAR([PKG_CONFIG_LIBDIR], [path overriding pkg-config's built-in search path])

if test "x$ac_cv_env_PKG_CONFIG_set" != "xset"; then
	AC_PATH_TOOL([PKG_CONFIG], [pkg-config])
fi
if test -n "$PKG_CONFIG"; then
	_pkg_min_version=m4_default([$1], [0.9.0])
	AC_MSG_CHECKING([pkg-config is at least version $_pkg_min_version])
	if $PKG_CONFIG --atleast-pkgconfig-version $_pkg_min_version; then
		AC_MSG_RESULT([yes])
	else
		AC_MSG_RESULT([no])
		PKG_CONFIG=""
	fi
fi[]dnl
])dnl PKG_PROG_PKG_CONFIG

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
