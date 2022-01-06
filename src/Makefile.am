noinst_LIBRARIES = libbip.a

libbip_a_SOURCES = conf.y lex.l \
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
bip_LDADD = libbip.a ${OPENSSL_LIBS}


bipmkpw_SOURCES = bipmkpw.c md5.c util.c
bipmkpw_CFLAGS = ${OPENSSL_CFLAGS} $(AM_CFLAGS)
AM_YFLAGS= -d
BUILT_SOURCES = conf.c conf.h lex.c

AM_CFLAGS=-Wall -Wextra -Werror \
	-O2 \
	-D_FORTIFY_SOURCE=2 \
	-fstack-protector-strong -fstack-clash-protection \
	-Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code \
	-Wpedantic -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wtrampolines -Walloca -Wvla -Warray-bounds=2 -Wimplicit-fallthrough=3 -Wtraditional-conversion -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 -Wconversion -Warith-conversion -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wformat-signedness -Wshadow -Wstrict-overflow=4 -Wundef -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wstack-usage=1000000 -Wcast-align=strict
