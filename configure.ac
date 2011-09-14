AC_PREREQ([2.64])
AC_INIT([bip], [0.8.8-git], [http://bip.milkypond.org/projects/bip/activity], [Bip Sexy IRC Proxy], [http://bip.milkypond.org/])
AM_INIT_AUTOMAKE([subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])
AC_CONFIG_SRCDIR([src/bip.h])
AC_CONFIG_HEADERS([src/config.h])

# Checks for programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
AM_PROG_LEX
AC_PROG_YACC

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h fcntl.h inttypes.h libintl.h limits.h malloc.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h sys/time.h termios.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_INT8_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_CHECK_FUNCS([ftruncate gethostname gettimeofday localtime_r memmove memset mkdir select socket strcasecmp strchr strcspn strdup strerror strrchr strstr])

# Deal with parameters

AC_ARG_ENABLE([debug], AS_HELP_STRING([--enable-debug], [Enable debug build]))
AC_ARG_WITH([openssl], AS_HELP_STRING([--without-openssl], [Disable SSL using OpenSSL]))  
AC_ARG_ENABLE([oidentd], AS_HELP_STRING([--enable-oidentd], [Enable oidentd support (bip overwrites ~/.oidentd.conf with this on!)]))
AC_ARG_ENABLE([pie], AS_HELP_STRING([--disable-pie], [Do not build a position independent executable]))

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
		AC_TRY_RUN([static int foo[30000]; int main () { return 0; }],
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

AC_CONFIG_FILES([Makefile])
AC_OUTPUT

AS_IF([test "x$with_openssl" != "xno"], [
echo OPENSSL: yes
])
echo DEBUG: $enable_debug $backtrace
echo OIDENTD: $enable_oidentd
echo PIE: $enable_pie

