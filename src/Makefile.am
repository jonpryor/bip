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
	util.c util.h

bin_PROGRAMS = bip bipmkpw

bip_SOURCES = bip_main.c
bip_LDADD = libbip.a

bipmkpw_SOURCES = bipmkpw.c md5.c util.c
AM_YFLAGS= -d
BUILT_SOURCES = conf.c conf.h lex.c
