noinst_LIBRARIES = libbip.a libbiplex.a

libbiplex_a_SOURCES = \
	conf.y lex.l

# Not adding AM_CFLAGS here, because many debian flex releases generate code
# that compares signed and unsigned integers. It looks like this issue is
# fixed by flex 2.6.5 which is unreleased.
libbiplex_a_CFLAGS = $(OPENSSL_CFLAGS)

libbip_a_SOURCES = \
	bip.c bip.h \
	connection.c connection.h \
	defaults.h \
	irc.c irc.h \
	line.c line.h \
	log.c log.h \
	md5.c md5.h \
	path_util.c path_util.h \
	tuple.h \
	util.c util.h \
	utils/base64.c utils/base64.h

libbip_a_CFLAGS = ${OPENSSL_CFLAGS} $(AM_CFLAGS)

bin_PROGRAMS = bip bipmkpw

bip_SOURCES = bip_main.c
bip_CFLAGS = ${OPENSSL_CFLAGS} $(AM_CFLAGS)
bip_LDADD = libbip.a libbiplex.a ${OPENSSL_LIBS}

bipmkpw_SOURCES = bipmkpw.c md5.c util.c
bipmkpw_CFLAGS = ${OPENSSL_CFLAGS} $(AM_CFLAGS)
bipmkpw_LDADD = libbip.a libbiplex.a $(OPENSSL_LIBS)

AM_YFLAGS= -d
BUILT_SOURCES = conf.c conf.h lex.c

# _BIP_WARNING_AS_ERROR = -Werror
# _BIP_GNU_LINKER_FLAGS = -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
_BIP_WARNING_AS_ERROR =
_BIP_GNU_LINKER_FLAGS =

AM_CFLAGS=-Wall -Wextra $(_BIP_WARNING_AS_ERROR) \
	-O2 \
	-D_FORTIFY_SOURCE=2 -D_C99_SOURCE=1 \
	-fstack-protector-strong -fstack-clash-protection \
	$(_BIP_GNU_LINKER_FLAGS) \
	-Wpedantic -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wtrampolines -Walloca -Wvla -Warray-bounds=2 -Wimplicit-fallthrough=3 -Wtraditional-conversion -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 -Wconversion -Warith-conversion -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wformat-signedness -Wshadow -Wstrict-overflow=4 -Wundef -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wstack-usage=1000000 -Wcast-align=strict
