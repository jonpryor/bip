/*
 * $Id: bip.c,v 1.39 2005/04/21 06:58:50 nohar Exp $
 *
 * This file is part of the bip project
 * Copyright (C) 2004,2005 Arnaud Cornet
 * Copyright (C) 2004,2005,2022 Loïc Gomez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdarg.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "irc.h"
#include "conf.h"
#include "path_util.h"
#include "tuple.h"
#include "log.h"
#include "bip.h"
#include "line.h"
#include "defaults.h"

#define S_CONF "bip.conf"

int sighup = 0;

char *conf_log_root;
char *conf_log_format;
int conf_log_level;
char *conf_ip;
unsigned short conf_port;
int conf_css;
#ifdef HAVE_LIBSSL
char *conf_ssl_certfile;
char *conf_client_ciphers;
char *conf_client_dh_file;
char *conf_server_default_ciphers;
#endif
int conf_daemonize;
char *conf_pid_file;
char *conf_biphome;
int conf_reconn_timer;

/* log options, for sure the trickiest :) */
int conf_log = DEFAULT_LOG;
int conf_log_system = DEFAULT_LOG_SYSTEM;
int conf_log_sync_interval = DEFAULT_LOG_SYNC_INTERVAL;

bip_t *_bip;
FILE *conf_global_log_file;

list_t *parse_conf(FILE *file, int *err);
void conf_die(bip_t *bip, char *fmt, ...);
static char *get_tuple_pvalue(list_t *tuple_l, int lex);
void bip_notify(struct link_client *ic, char *fmt, ...);
void adm_list_connections(struct link_client *ic, struct bipuser *bu);
void free_conf(list_t *l);


static void hash_binary(char *hex, unsigned char **password, unsigned int *seed)
{
	unsigned char *md5;
	unsigned int buf;
	int i;

	if (strlen(hex) != 40)
		fatal("Incorrect password format %s\n", hex);

	md5 = bip_malloc((size_t)20);
	for (i = 0; i < 20; i++) {
		sscanf(hex + 2 * i, "%02x", &buf);
// conversion from ‘unsigned int’ to ‘unsigned char’ may change value
// we're parsing a text (hex) so buf won't ever be something else than a char
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wconversion"
		md5[i] = buf;
#pragma GCC diagnostic pop
	}

	*seed = 0;
	sscanf(hex, "%02x", &buf);
	*seed |= buf << 24;
	sscanf(hex + 2, "%02x", &buf);
	*seed |= buf << 16;
	sscanf(hex + 2 * 2, "%02x", &buf);
	*seed |= buf << 8;
	sscanf(hex + 2 * 3, "%02x", &buf);
	*seed |= buf;

	MAYFREE(*password);
	*password = md5;
}

static int add_server(bip_t *bip, struct server *s, list_t *data)
{
	struct tuple *t;

	s->port = 6667; /* default port */

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_HOST:
			MOVE_STRING(s->host, t->pdata);
			break;
		case LEX_PORT:
			s->port = (unsigned short)t->ndata;
			break;
		default:
			fatal("Config error in server block (%d)", t->type);
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	if (!s->host) {
		free(s);
		conf_die(bip, "Server conf: host not set");
		return 0;
	}
	return 1;
}

#define ERRBUFSZ 128

extern list_t *root_list;
extern int yyparse(void);

void conf_die(bip_t *bip, char *fmt, ...)
{
	va_list ap;
	size_t size = ERRBUFSZ;
	int n;
	char *error = bip_malloc(size);

	for (;;) {
		va_start(ap, fmt);
		n = vsnprintf(error, size, fmt, ap);
		va_end(ap);
		if (n > -1 && (unsigned int)n < size) {
			list_add_last(&bip->errors, error);
			break;
		}
		if (n > -1)
			size = (unsigned int)n + 1;
		else
			size *= 2;
		error = bip_realloc(error, size);
	}
	va_start(ap, fmt);
	_mylog(LOG_ERROR, fmt, ap);
	va_end(ap);
}


/* RACE CONDITION! */
int do_pid_stuff(void)
{
	char hname[512];
	FILE *f;
	int fd;
	// size is conf_pid_file + hname max + %ld max + two '.'.
	size_t longpath_max = strlen(conf_pid_file) + 512 + 3 + 20;
	char *longpath = bip_malloc(longpath_max + 1);

try_again:
	fd = -1;
	f = fopen(conf_pid_file, "r");
	if (f)
		goto pid_is_there;
	if (gethostname(hname, (size_t)511) == -1)
		fatal("%s %s", "gethostname", strerror(errno));
	hname[511] = 0;
	snprintf(longpath, longpath_max - 1, "%s.%s.%ld", conf_pid_file, hname,
		 (long)getpid());
	longpath[longpath_max] = 0;
	if ((fd = open(longpath, O_CREAT | O_WRONLY, S_IWUSR | S_IRUSR)) == -1)
		fatal("Cannot write to PID file (%s) %s", longpath,
		      strerror(errno));
	if (link(longpath, conf_pid_file) == -1) {
		struct stat buf;
		if (stat(longpath, &buf) == -1) {
			if (buf.st_nlink != 2) {
				f = fopen(conf_pid_file, "r");
				goto pid_is_there;
			}
		}
	}
	unlink(longpath);
	free(longpath);
	return fd;
pid_is_there : {
	pid_t pid;
	size_t p;
	if (fd != -1)
		close(fd);
	if (f) {
		int c = fscanf(f, "%zu", (size_t *)&p);
		fclose(f);
		pid = (pid_t)p;
		if (c != 1 || p == 0) {
			mylog(LOG_INFO,
			      "pid file found but invalid "
			      "data inside. Continuing...\n");
			if (unlink(conf_pid_file)) {
				fatal("Cannot delete pid file '%s', "
				      "check permissions.\n",
				      conf_pid_file);
			}
			goto try_again;
		}
	} else
		pid = 0;
	int kr = kill(pid, 0);
	if (kr == -1 && (errno == ESRCH || errno == EPERM)) {
		/* that's not bip! */
		if (unlink(conf_pid_file)) {
			fatal("Cannot delete pid file '%s', check "
			      "permissions.\n",
			      conf_pid_file);
		}
		goto try_again;
	}
	if (pid)
		mylog(LOG_INFO, "pid file found (pid %ld).", pid);
	mylog(LOG_FATAL, "Another instance of bip is certainly running.");
	mylog(LOG_FATAL,
	      "If you are sure this is not the case remove"
	      " %s.",
	      conf_pid_file);
	exit(2);
}
	free(longpath);
	return 0;
}

void reload_config(int i)
{
	(void)i;
	sighup = 1;
	_bip->reloading_client = NULL;
}

void rlimit_cpu_reached(int i)
{
	(void)i;
	mylog(LOG_WARN,
	      "This process has reached the CPU time usage limit. "
	      "It means bip will be killed by the Operating System soon.");
}

void rlimit_bigfile_reached(int i)
{
	(void)i;
	mylog(LOG_WARN,
	      "A file has reached the max size this process is "
	      "allowed to create. The file will not be written correctly, "
	      "an error message should follow. This is not fatal.");
}

void bad_quit(int i)
{
	list_iterator_t it;
	for (list_it_init(&_bip->link_list, &it); list_it_item(&it);
	     list_it_next(&it)) {
		struct link *l = list_it_item(&it);
		struct link_server *ls = l->l_server;
		if (ls && l->s_state == IRCS_CONNECTED) {
			write_line_fast(CONN(ls),
					"QUIT :Coyote finally "
					"caught me\r\n");
		}
	}
	unlink(conf_pid_file);
	exit(i);
}

static int add_network(bip_t *bip, list_t *data)
{
	struct tuple *t;
	struct network *n;
	int i;
	int r;

	char *name = get_tuple_pvalue(data, LEX_NAME);

	if (name == NULL) {
		conf_die(bip, "Network with no name");
		return 0;
	}
	n = hash_get(&bip->networks, name);
	if (n) {
		for (i = 0; i < n->serverc; i++)
			free(n->serverv[i].host);
		free(n->serverv);
		n->serverv = NULL;
		n->serverc = 0;
	} else {
		n = bip_calloc(sizeof(struct network), (size_t)1);
		hash_insert(&bip->networks, name, n);
	}

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			MOVE_STRING(n->name, t->pdata);
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL:
			n->ssl = t->ndata;
			break;
		case LEX_CIPHERS:
			MOVE_STRING(n->ciphers, t->pdata);
			break;
#endif
		case LEX_SERVER:
			if (n->serverc < 0) {
				conf_die(bip,
					 "internal error in network statement");
				return 0;
			}

			n->serverv = bip_realloc(
				n->serverv, (unsigned int)(n->serverc + 1)
						    * sizeof(struct server));
			n->serverc++;
			memset(&n->serverv[n->serverc - 1], 0,
			       sizeof(struct server));
			r = add_server(bip, &n->serverv[n->serverc - 1],
				       t->pdata);
			if (!r) {
				n->serverc--;
				return 0;
			}
			free(t->pdata);
			t->pdata = NULL;
			break;
		default:
			conf_die(bip, "unknown keyword in network statement");
			return 0;
			break;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}

#ifdef HAVE_LIBSSL
	if (!n->ciphers) {
		n->ciphers = conf_server_default_ciphers;
	}
#endif
	if (n->serverc == 0) {
		conf_die(bip, "No server in network: %s", n->name);
		hash_remove_if_exists(&bip->networks, name);
		free(n->name);
		free(n);
		n = NULL;
		return 0;
	}
	return 1;
}

void adm_bip_delconn(bip_t *bip, struct link_client *ic, const char *conn_name)
{
	struct bipuser *user = LINK(ic)->user;
	struct link *l;

	if (!(l = hash_get(&user->connections, conn_name))) {
		bip_notify(ic, "cannot find this connection");
		return;
	}

	bip_notify(ic, "deleting");
	link_kill(bip, l);
}

void adm_bip_addconn(bip_t *bip, struct link_client *ic, const char *conn_name,
		     const char *network_name)
{
	struct bipuser *user = LINK(ic)->user;
	struct network *network;

	/* check name uniqueness */
	if (hash_get(&user->connections, conn_name)) {
		bip_notify(ic, "connection name already exists for this user.");
		return;
	}

	/* check we know about this network */
	network = hash_get(&bip->networks, network_name);
	if (!network) {
		bip_notify(ic, "no such network name");
		return;
	}

	struct link *l;
	l = irc_link_new();
	l->name = bip_strdup(conn_name);
	hash_insert(&user->connections, conn_name, l);
	list_add_last(&bip->link_list, l);
	l->user = user;
	l->network = network;
	l->log = log_new(user, conn_name);
#ifdef HAVE_LIBSSL
	l->ssl_check_mode = user->ssl_check_mode;
	l->untrusted_certs = sk_X509_new_null();
#endif


#define SCOPY(member)                                                          \
	l->member = (LINK(ic)->member ? bip_strdup(LINK(ic)->member) : NULL)
#define ICOPY(member) l->member = LINK(ic)->member

	SCOPY(connect_nick);
	SCOPY(username);
	SCOPY(realname);
	/* we don't copy server password */
	SCOPY(vhost);
	ICOPY(follow_nick);
	ICOPY(ignore_first_nick);
	SCOPY(away_nick);
	SCOPY(no_client_away_msg);
	/* we don't copy on_connect_send */
#ifdef HAVE_LIBSSL
	ICOPY(ssl_check_mode);
#endif
#undef SCOPY
#undef ICOPY
	bip_notify(ic, "connection added, you should soon be able to connect");
}

static int add_connection(bip_t *bip, struct bipuser *user, list_t *data)
{
	struct tuple *t, *t2;
	struct link *l;
	struct chan_info *ci;
	char *name = get_tuple_pvalue(data, LEX_NAME);

	if (name == NULL) {
		conf_die(bip, "Connection with no name");
		return 0;
	}
	l = hash_get(&user->connections, name);
	if (!l) {
		l = irc_link_new();
		hash_insert(&user->connections, name, l);
		list_add_last(&bip->link_list, l);
		l->user = user;
		l->log = log_new(user, name);
#ifdef HAVE_LIBSSL
		l->ssl_check_mode = user->ssl_check_mode;
		l->untrusted_certs = sk_X509_new_null();
#endif
	} else {
		l->network = NULL;
		log_reset_all(l->log);
	}

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			MOVE_STRING(l->name, t->pdata);
			break;
		case LEX_NETWORK:
			l->network = hash_get(&bip->networks, t->pdata);
			if (!l->network) {
				conf_die(bip, "Undefined network %s.\n",
					 t->pdata);
				return 0;
			}
			break;
		case LEX_NICK:
			if (!is_valid_nick(t->pdata)) {
				conf_die(bip, "Invalid nickname %s.", t->pdata);
				return 0;
			}
			MOVE_STRING(l->connect_nick, t->pdata);
			break;
		case LEX_USER:
			MOVE_STRING(l->username, t->pdata);
			break;
		case LEX_REALNAME:
			MOVE_STRING(l->realname, t->pdata);
			break;
		case LEX_PASSWORD:
			MOVE_STRING(l->s_password, t->pdata);
			break;
		case LEX_SASL_USERNAME:
			MOVE_STRING(l->sasl_username, t->pdata);
			break;
		case LEX_SASL_PASSWORD:
			MOVE_STRING(l->sasl_password, t->pdata);
			break;
		case LEX_SASL_MECHANISM:
			if (strcmp(t->pdata, "PLAIN") == 0) {
				l->sasl_mechanism = SASL_AUTH_PLAIN;
			} else if (strcmp(t->pdata, "EXTERNAL") == 0) {
				l->sasl_mechanism = SASL_AUTH_EXTERNAL;
			} else {
				conf_die(bip, "Unsupported SASL mechanism %s.",
					 t->pdata);
				return 0;
			}
			break;
		case LEX_VHOST:
			MOVE_STRING(l->vhost, t->pdata);
			break;
		case LEX_CHANNEL:
			name = get_tuple_pvalue(t->pdata, LEX_NAME);
			if (name == NULL) {
				conf_die(bip, "Channel with no name");
				return 0;
			}

			ci = hash_get(&l->chan_infos, name);
			if (!ci) {
				ci = chan_info_new();
				hash_insert(&l->chan_infos, name, ci);
				/* FIXME: this order is not reloaded */
				list_add_last(&l->chan_infos_order, ci);
				ci->backlog = 1;
			}

			while ((t2 = list_remove_first(t->pdata))) {
				switch (t2->type) {
				case LEX_NAME:
					MOVE_STRING(ci->name, t2->pdata);
					break;
				case LEX_KEY:
					MOVE_STRING(ci->key, t2->pdata);
					break;
				case LEX_BACKLOG:
					ci->backlog = t2->ndata;
					break;
				default:
					conf_die(
						bip,
						"Unknown keyword in channel block (%d)",
						t2->type);
					return 0;
				}
				if (t2->tuple_type == TUPLE_STR && t2->pdata)
					free(t2->pdata);
				free(t2);
			}
			list_free(t->pdata);
			break;
		case LEX_AUTOJOIN_ON_KICK:
			l->autojoin_on_kick = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_FOLLOW_NICK:
			l->follow_nick = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_IGN_FIRST_NICK:
			l->ignore_first_nick = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_IGNORE_CAPAB:
			l->ignore_server_capab = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_AWAY_NICK:
			MOVE_STRING(l->away_nick, t->pdata);
			break;
		case LEX_NO_CLIENT_AWAY_MSG:
			MOVE_STRING(l->no_client_away_msg, t->pdata);
			break;
		case LEX_ON_CONNECT_SEND:
			list_add_last(&l->on_connect_send, t->pdata);
			t->pdata = NULL;
			break;
		case LEX_LOG:
			l->log->log_to_file = (t->ndata > 0 ? 1 : 0);
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL_CHECK_MODE:
			if (strcmp(t->pdata, "basic") == 0)
				l->ssl_check_mode = SSL_CHECK_BASIC;
			if (strcmp(t->pdata, "ca") == 0)
				l->ssl_check_mode = SSL_CHECK_CA;
			if (strcmp(t->pdata, "none") == 0)
				l->ssl_check_mode = SSL_CHECK_NONE;
			break;
#else
		case LEX_SSL_CHECK_MODE:
			mylog(LOG_WARN,
			      "Found SSL option whereas bip is "
			      "not built with SSL support.");
			break;
#endif
		default:
			conf_die(bip,
				 "Unknown keyword in connection "
				 "statement");
			return 0;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	/* checks that can only be here, or must */
	if (!l->network) {
		conf_die(bip, "Missing network in connection block");
		return 0;
	}
	if (!l->connect_nick) {
		if (!user->default_nick) {
			conf_die(bip, "No nick set and no default nick.");
			return 0;
		}
		l->connect_nick = bip_strdup(user->default_nick);
	}
	if (!l->username) {
		if (!user->default_username) {
			conf_die(bip,
				 "No username set and no default "
				 "username.");
			return 0;
		}
		l->username = bip_strdup(user->default_username);
	}
	if (!l->realname) {
		if (!user->default_realname) {
			conf_die(bip,
				 "No realname set and no default "
				 "realname.");
			return 0;
		}
		l->realname = bip_strdup(user->default_realname);
	}

	if (l->sasl_username && !l->sasl_password) {
		conf_die(bip, "sasl_username set without sasl_password.");
		return 0;
	}

	if (!l->sasl_username && l->sasl_password) {
		conf_die(bip, "sasl_password set without sasl_username.");
		return 0;
	}

	if (l->sasl_mechanism == SASL_AUTH_PLAIN
	    && (!l->sasl_username || !l->sasl_password)) {
		conf_die(
			bip,
			"SASL mechanism PLAIN requires username and password.");
		return 0;
	}
	if (l->sasl_username && !l->sasl_mechanism)
		l->sasl_mechanism = SASL_AUTH_PLAIN;

	l->in_use = 1;
	return 1;
}

static char *get_tuple_pvalue(list_t *tuple_l, int lex)
{
	struct tuple *t;
	list_iterator_t it;

	for (list_it_init(tuple_l, &it); (t = list_it_item(&it));
	     list_it_next(&it)) {
		if (t->type == lex)
			return t->pdata;
	}
	return NULL;
}

static int get_tuple_nvalue(list_t *tuple_l, int lex)
{
	struct tuple *t;
	list_iterator_t it;

	for (list_it_init(tuple_l, &it); (t = list_it_item(&it));
	     list_it_next(&it)) {
		if (t->type == lex)
			return t->ndata;
	}
	return -1;
}

enum BLTimestamp lex_backlog_timestamp(char *tdata)
{
	if (strcmp(tdata, "time") == 0) {
		return BLTSTime;
	} else if (strcmp(tdata, "datetime") == 0) {
		return BLTSDateTime;
	} else {
		return BLTSNone;
	}
}

struct historical_directives {
	int always_backlog;
	int backlog;
	int bl_msg_only;
	int backlog_lines;
	enum BLTimestamp backlog_timestamp;
	int blreset_on_talk;
};

static int add_user(bip_t *bip, list_t *data, struct historical_directives *hds)
{
	int r;
	struct tuple *t;
	struct bipuser *u;
	char *name = get_tuple_pvalue(data, LEX_NAME);
	list_t connection_list, *cl;

	list_init(&connection_list, NULL);

	if (name == NULL) {
		conf_die(bip, "User with no name");
		return 0;
	}
	u = hash_get(&bip->users, name);
	if (!u) {
		u = bip_calloc(sizeof(struct bipuser), (size_t)1);
		hash_insert(&bip->users, name, u);
		hash_init(&u->connections, HASH_NOCASE);
		u->admin = 0;
		u->backlog = DEFAULT_BACKLOG;
		u->always_backlog = DEFAULT_ALWAYS_BACKLOG;
		u->bl_msg_only = DEFAULT_BL_MSG_ONLY;
		u->backlog_lines = DEFAULT_BACKLOG_LINES;
		u->backlog_timestamp = DEFAULT_BACKLOG_TIMESTAMP;
		u->blreset_on_talk = DEFAULT_BLRESET_ON_TALK;
		u->blreset_connection = DEFAULT_BLRESET_CONNECTION;
		u->bip_use_notice = DEFAULT_BIP_USE_NOTICE;
	}

	u->backlog = (hds->backlog > 0 ? 1 : 0);
	u->always_backlog = (hds->always_backlog > 0 ? 1 : 0);
	u->bl_msg_only = (hds->bl_msg_only > 0 ? 1 : 0);
	u->backlog_lines = (hds->backlog_lines > 0 ? 1 : 0);
	u->backlog_timestamp = (hds->backlog_timestamp > 0 ? 1 : 0);
	u->blreset_on_talk = (hds->blreset_on_talk > 0 ? 1 : 0);

	while ((t = list_remove_first(data))) {
		switch (t->type) {
		case LEX_NAME:
			MOVE_STRING(u->name, t->pdata);
			break;
		case LEX_ADMIN:
			u->admin = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_PASSWORD:
			hash_binary(t->pdata, &u->password, &u->seed);
			free(t->pdata);
			t->pdata = NULL;
			break;
		case LEX_DEFAULT_NICK:
			MOVE_STRING(u->default_nick, t->pdata);
			break;
		case LEX_DEFAULT_USER:
			MOVE_STRING(u->default_username, t->pdata);
			break;
		case LEX_DEFAULT_REALNAME:
			MOVE_STRING(u->default_realname, t->pdata);
			break;
		case LEX_ALWAYS_BACKLOG:
			u->always_backlog = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_BACKLOG:
			u->backlog = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_BL_MSG_ONLY:
			u->bl_msg_only = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_BACKLOG_LINES:
			u->backlog_lines = t->ndata;
			break;
		case LEX_BACKLOG_NO_TIMESTAMP:
			u->backlog_timestamp = t->ndata ? BLTSNone : BLTSTime;
			break;
		case LEX_BACKLOG_TIMESTAMP:
			u->backlog_timestamp = lex_backlog_timestamp(t->pdata);
			break;
		case LEX_BLRESET_ON_TALK:
			u->blreset_on_talk = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_BLRESET_CONNECTION:
			u->blreset_connection = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_BIP_USE_NOTICE:
			u->bip_use_notice = (t->ndata > 0 ? 1 : 0);
			break;
		case LEX_CONNECTION:
			list_add_last(&connection_list, t->pdata);
			t->pdata = NULL;
			break;
#ifdef HAVE_LIBSSL
		case LEX_SSL_CHECK_MODE:
			if (!strcmp(t->pdata, "basic"))
				u->ssl_check_mode = SSL_CHECK_BASIC;
			if (!strcmp(t->pdata, "ca"))
				u->ssl_check_mode = SSL_CHECK_CA;
			if (!strcmp(t->pdata, "none"))
				u->ssl_check_mode = SSL_CHECK_NONE;
			free(t->pdata);
			t->pdata = NULL;
			break;
		case LEX_SSL_CHECK_STORE:
			MOVE_STRING(u->ssl_check_store, t->pdata);
			break;
		case LEX_SSL_CLIENT_CERTFILE:
			MOVE_STRING(u->ssl_client_certfile, t->pdata);
			break;
#else
		case LEX_SSL_CLIENT_CERTFILE:
		case LEX_SSL_CHECK_MODE:
		case LEX_SSL_CHECK_STORE:
			mylog(LOG_WARN,
			      "Found SSL option whereas bip is "
			      "not built with SSL support.");
			break;
#endif
		default:
			conf_die(bip, "Unknown keyword in user statement");
			return 0;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	if (!u->password) {
		conf_die(bip, "Missing password in user block");
		return 0;
	}

	while ((cl = list_remove_first(&connection_list))) {
		r = add_connection(bip, u, cl);
		free(cl);
		if (!r)
			return 0;
	}

	u->in_use = 1;
	return 1;
}

static int validate_config(bip_t *bip)
{
	/* nick username realname or default_{nick,username,realname} in user */
	hash_iterator_t it, sit, cit;
	struct bipuser *user;
	struct link *link;
	struct chan_info *ci;
	int r = 1;

	for (hash_it_init(&bip->users, &it); (user = hash_it_item(&it));
	     hash_it_next(&it)) {
		for (hash_it_init(&user->connections, &sit);
		     (link = hash_it_item(&sit)); hash_it_next(&sit)) {
			if (!user->default_nick || !user->default_username
			    || !user->default_realname) {
				if ((!link->username && !user->default_username)
				    || (!link->connect_nick
					&& !user->default_nick)
				    || (!link->realname
					&& !user->default_realname)) {
					conf_die(bip,
						 "user %s, "
						 "connection %s: you must defin"
						 "e nick, user and realname.",
						 user->name, link->name);
					link_kill(bip, link);
					r = 0;
					continue;
				}
			}

			for (hash_it_init(&link->chan_infos, &cit);
			     (ci = hash_it_item(&cit)); hash_it_next(&cit)) {
				if (!ci->name) {
					conf_die(bip,
						 "user %s, "
						 "connection "
						 "%s: channel must have"
						 "a name.",
						 user->name, link->name);
					r = 0;
					continue;
				}
			}
		}

		if (user->backlog && !conf_log && user->backlog_lines == 0) {
			conf_die(bip,
				 "If conf_log = false, you must set "
				 "backlog_"
				 "lines to a non-nul value for each user with"
				 "backlog = true. Faulty user is %s",
				 user->name);
			r = 0;
			continue;
		}
	}

	if (!strstr(conf_log_format, "%u")) {
		hash_it_init(&bip->users, &it);
		if (hash_it_item(&it)) {
			// hash contains at least one element
			hash_it_next(&it);
			if (hash_it_item(&it)) {
				// hash contains at least two elements
				mylog(LOG_WARN,
				      "log_format does not contain %%u, all users'"
				      " logs will be mixed !");
			}
		}
	}
	return r;
}

void clear_marks(bip_t *bip)
{
	list_iterator_t lit;
	hash_iterator_t hit;

	for (list_it_init(&bip->link_list, &lit); list_it_item(&lit);
	     list_it_next(&lit))
		((struct link *)list_it_item(&lit))->in_use = 0;
	for (hash_it_init(&bip->users, &hit); hash_it_item(&hit);
	     hash_it_next(&hit))
		((struct bipuser *)hash_it_item(&hit))->in_use = 0;
}

void user_kill(bip_t *bip, struct bipuser *user)
{
	(void)bip;
	if (!hash_is_empty(&user->connections))
		fatal("user_kill, user still has connections");
	free(user->name);
	free(user->password);
	MAYFREE(user->default_nick);
	MAYFREE(user->default_username);
	MAYFREE(user->default_realname);

#ifdef HAVE_LIBSSL
	MAYFREE(user->ssl_check_store);
	MAYFREE(user->ssl_client_certfile);
#endif
	free(user);
}

void sweep(bip_t *bip)
{
	list_iterator_t lit;
	hash_iterator_t hit;

	for (list_it_init(&bip->link_list, &lit); list_it_item(&lit);
	     list_it_next(&lit)) {
		struct link *l = ((struct link *)list_it_item(&lit));
		if (!l->in_use) {
			mylog(LOG_INFO, "Administratively killing %s/%s",
			      l->user->name, l->name);
			list_remove_if_exists(&bip->conn_list, l);
			link_kill(bip, l);
			list_it_remove(&lit);
		}
	}
	for (hash_it_init(&bip->users, &hit); hash_it_item(&hit);
	     hash_it_next(&hit)) {
		struct bipuser *u = (struct bipuser *)hash_it_item(&hit);
		if (!u->in_use) {
			hash_it_remove(&hit);
			user_kill(bip, u);
		}
	}
}

int fireup(bip_t *bip, FILE *conf)
{
	int r;
	struct tuple *t;
	int err = 0;
	struct historical_directives hds;
	char *l;

	clear_marks(bip);
	while ((l = list_remove_first(&bip->errors)))
		free(l);
	parse_conf(conf, &err);
	if (err) {
		free_conf(root_list);
		root_list = NULL;
		return 0;
	}

#define SET_HV(d, n)                                                           \
	do {                                                                   \
		int __gtv = get_tuple_nvalue(root_list, LEX_##n);              \
		if (__gtv != -1)                                               \
			d = __gtv;                                             \
		else                                                           \
			d = DEFAULT_##n;                                       \
	} while (0);
	SET_HV(hds.always_backlog, ALWAYS_BACKLOG);
	SET_HV(hds.backlog, BACKLOG);
	SET_HV(hds.bl_msg_only, BL_MSG_ONLY);
	SET_HV(hds.backlog_lines, BACKLOG_LINES);
	SET_HV(hds.backlog_timestamp, BACKLOG_TIMESTAMP);
	SET_HV(hds.blreset_on_talk, BLRESET_ON_TALK);
#undef SET_HV

	while ((t = list_remove_first(root_list))) {
		switch (t->type) {
		case LEX_LOG_SYNC_INTERVAL:
			conf_log_sync_interval = t->ndata;
			break;
		case LEX_LOG:
			conf_log = t->ndata;
			break;
		case LEX_LOG_SYSTEM:
			conf_log_system = t->ndata;
			break;
		case LEX_LOG_ROOT:
			MOVE_STRING(conf_log_root, t->pdata);
			break;
		case LEX_LOG_FORMAT:
			MOVE_STRING(conf_log_format, t->pdata);
			break;
		case LEX_LOG_LEVEL:
			conf_log_level = t->ndata;
			break;
		case LEX_IP:
			MOVE_STRING(conf_ip, t->pdata);
			break;
		case LEX_PORT:
			conf_port = (unsigned short)t->ndata;
			break;
		case LEX_RECONN_TIMER:
			conf_reconn_timer = t->ndata;
			break;
#ifdef HAVE_LIBSSL
		case LEX_DEFAULT_CIPHERS:
			MOVE_STRING(conf_server_default_ciphers, t->pdata);
			break;
		case LEX_CSS_CIPHERS:
			MOVE_STRING(conf_client_ciphers, t->pdata);
			break;
		case LEX_CSS:
			conf_css = t->ndata;
			break;
		case LEX_CSS_PEM:
			MOVE_STRING(conf_ssl_certfile, t->pdata);
			break;
		case LEX_DH_PARAM:
			MOVE_STRING(conf_client_dh_file, t->pdata);
			break;
#else
		case LEX_DEFAULT_CIPHERS:
		case LEX_CSS:
		case LEX_CSS_CIPHERS:
		case LEX_CSS_PEM:
		case LEX_DH_PARAM:
			mylog(LOG_WARN,
			      "Found SSL option whereas bip is "
			      "not built with SSL support.");
			break;
#endif
		case LEX_PID_FILE:
			MOVE_STRING(conf_pid_file, t->pdata);
			break;
		case LEX_WRITE_OIDENTD:
			bip->write_oidentd = t->ndata;
			break;
		case LEX_OIDENTD_FILE:
			MOVE_STRING(bip->oidentdpath, t->pdata);
			break;
		case LEX_ALWAYS_BACKLOG:
			hds.always_backlog = t->ndata;
			break;
		case LEX_BACKLOG:
			hds.backlog = t->ndata;
			break;
		case LEX_BL_MSG_ONLY:
			hds.bl_msg_only = t->ndata;
			break;
		case LEX_BACKLOG_LINES:
			hds.backlog_lines = t->ndata;
			break;
		case LEX_BACKLOG_NO_TIMESTAMP:
			hds.backlog_timestamp = t->ndata ? BLTSNone : BLTSTime;
			break;
		case LEX_BACKLOG_TIMESTAMP:
			hds.backlog_timestamp = lex_backlog_timestamp(t->pdata);
			break;
		case LEX_BLRESET_ON_TALK:
			hds.blreset_on_talk = t->ndata;
			break;
		case LEX_NETWORK:
			r = add_network(bip, t->pdata);
			list_free(t->pdata);
			if (!r)
				goto out_conf_error;
			break;
		case LEX_USER:
			r = add_user(bip, t->pdata, &hds);
			list_free(t->pdata);
			if (!r)
				goto out_conf_error;
			break;
		default:
			conf_die(bip, "Config error in base config (%d)",
				 t->type);
			goto out_conf_error;
		}
		if (t->tuple_type == TUPLE_STR && t->pdata)
			free(t->pdata);
		free(t);
	}
	free(root_list);
	root_list = NULL;

	if (validate_config(bip)) {
		sweep(bip);
		return 1;
	} else {
		return 0;
	}
out_conf_error:
	free_conf(root_list);
	root_list = NULL;
	return 0;
}

void check_rlimits(void)
{
	int r, cklim;
	struct rlimit lt;

	cklim = 0;

#ifdef RLIMIT_AS
	r = getrlimit(RLIMIT_AS, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
		      strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN,
			      "virtual memory rlimit active, "
			      "bip may be KILLED by the system");
			cklim = 1;
		}
	}
#endif

	r = getrlimit(RLIMIT_CPU, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
		      strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN,
			      "CPU rlimit active, bip may "
			      "be OFTEN KILLED by the system");
			cklim = 1;
		}
	}

	r = getrlimit(RLIMIT_FSIZE, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
		      strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN,
			      "FSIZE rlimit active, bip will "
			      "fail to create files of size greater than "
			      "%d bytes.",
			      (int)lt.rlim_max);
			cklim = 1;
		}
	}

	r = getrlimit(RLIMIT_NOFILE, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
		      strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY && lt.rlim_max < 256) {
			mylog(LOG_WARN,
			      "opened files count rlimit "
			      "active, bip will not be allowed to open more "
			      "than %d files at a time",
			      (int)lt.rlim_max);
			cklim = 1;
		}
	}

	r = getrlimit(RLIMIT_STACK, &lt);
	if (r) {
		mylog(LOG_ERROR, "getrlimit(): failed with %s",
		      strerror(errno));
	} else {
		if (lt.rlim_max != RLIM_INFINITY) {
			mylog(LOG_WARN,
			      "stack rlimit active, "
			      "bip may be KILLED by the system");
			cklim = 1;
		}
	}

	if (cklim)
		mylog(LOG_WARN, "You can check your limits with `ulimit -a'");
}

#define RET_STR_LEN 256
#define LINE_SIZE_LIM 70

void adm_print_connection(struct link_client *ic, struct link *lnk,
			  struct bipuser *bu)
{
	hash_iterator_t lit;
	char buf[LINE_SIZE_LIM + 1];
	char *bufpos = buf;
	size_t remaining = LINE_SIZE_LIM;

	if (!bu)
		bu = lnk->user;

	bip_notify(ic, "* %s to %s as \"%s\" (%s!%s) :", lnk->name,
		   lnk->network->name,
		   (lnk->realname ? lnk->realname : bu->default_realname),
		   (lnk->connect_nick ? lnk->connect_nick : bu->default_nick),
		   (lnk->username ? lnk->username : bu->default_username));

	bufpos = bip_strcat_fit(&remaining, bufpos, "  Options:");
	// This should not happen, unless LINE_SIZE_LIM is too low
	if (!bufpos)
		goto limittoolow;

	if (lnk->follow_nick) {
		bufpos = bip_strcat_fit(&remaining, bufpos, " follow_nick");
		if (!bufpos) {
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = bip_strcat_fit(&remaining, bufpos,
						"      follow_nick");
			if (!bufpos)
				goto limittoolow;
		}
	}
	if (lnk->ignore_first_nick) {
		bufpos = bip_strcat_fit(&remaining, bufpos,
					" ignore_first_nick");
		if (!bufpos) {
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = bip_strcat_fit(&remaining, bufpos,
						"      ignore_first_nick");
			if (!bufpos)
				goto limittoolow;
		}
	}
	if (lnk->away_nick) {
		bufpos = bip_strcatf_fit(&remaining, bufpos, " away_nick=%s",
					 lnk->away_nick);
		if (!bufpos) {
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = bip_strcatf_fit(&remaining, bufpos,
						 "      away_nick=%s",
						 lnk->away_nick);
			if (!bufpos)
				goto limittoolow;
		}
	}
	if (lnk->no_client_away_msg) {
		bufpos = bip_strcatf_fit(&remaining, bufpos,
					 " no_client_away_msg=%s",
					 lnk->no_client_away_msg);
		if (!bufpos) {
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = bip_strcatf_fit(&remaining, bufpos,
						 "      no_client_away_msg=%s",
						 lnk->no_client_away_msg);
			if (!bufpos)
				goto limittoolow;
		}
	}
	if (lnk->vhost) {
		bufpos = bip_strcatf_fit(&remaining, bufpos, " vhost=%s",
					 lnk->vhost);
		if (!bufpos) {
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = bip_strcatf_fit(&remaining, bufpos,
						 "      vhost=%s", lnk->vhost);
			if (!bufpos)
				goto limittoolow;
		}
	}
	if (lnk->bind_port) {
		bufpos = bip_strcatf_fit(&remaining, bufpos, " bind_port=%s",
					 lnk->bind_port);
		if (!bufpos) {
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = bip_strcatf_fit(&remaining, bufpos,
						 "      bind_port=%s",
						 lnk->bind_port);
			if (!bufpos)
				goto limittoolow;
		}
	}
	buf[LINE_SIZE_LIM] = 0;
	bip_notify(ic, "%s", buf);
	remaining = LINE_SIZE_LIM;
	bufpos = buf;

	list_iterator_t itocs;
	for (list_it_init(&lnk->on_connect_send, &itocs);
	     list_it_item(&itocs);) {
		bufpos = bip_strcatf_fit(&remaining, bufpos, "%s",
					 (char *)list_it_item(&itocs));
		if (!bufpos) {
			// if oversized, print and reset
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = buf;
			continue;
		} else {
			// if ok, go to next item
			list_it_next(&itocs);
		}
	}

	buf[LINE_SIZE_LIM] = 0;
	bip_notify(ic, "%s", buf);
	remaining = LINE_SIZE_LIM;
	bufpos = buf;


	// TODO : check channels struct
	bufpos = bip_strcat_fit(&remaining, bufpos,
				"  Channels (* with key, ` no backlog)");
	if (!bufpos)
		goto limittoolow;

	for (hash_it_init(&lnk->chan_infos, &lit); hash_it_item(&lit);
	     hash_it_next(&lit)) {
		struct chan_info *ch = hash_it_item(&lit);

		bufpos = bip_strcatf_fit(&remaining, bufpos, "%s%s%s", ch->name,
					 (ch->key ? "*" : ""),
					 (ch->backlog ? "" : "`"));
		if (!bufpos) {
			buf[LINE_SIZE_LIM] = 0;
			bip_notify(ic, "%s", buf);
			remaining = LINE_SIZE_LIM;
			bufpos = buf;
		}
	}

	buf[LINE_SIZE_LIM] = 0;
	bip_notify(ic, "%s", buf);
	remaining = LINE_SIZE_LIM;
	bufpos = buf;

	bufpos = bip_strcat_fit(&remaining, bufpos, "  Status: ");
	if (!bufpos)
		goto limittoolow;
	switch (lnk->s_state) {
	case IRCS_NONE:
		bufpos = bip_strcat_fit(&remaining, bufpos, "not started");
		if (!bufpos)
			goto limittoolow;
		break;
	case IRCS_CONNECTING:
		bufpos = bip_strcatf_fit(&remaining, bufpos,
					 "connecting... attempts: %d, last: %s",
					 lnk->s_conn_attempt,
					 hrtime(lnk->last_connection_attempt));
		if (!bufpos)
			goto noroomstatus;
		break;
	case IRCS_CONNECTED:
		bufpos = bip_strcat_fit(&remaining, bufpos, "connected !");
		if (!bufpos)
			goto limittoolow;
		break;
	case IRCS_WAS_CONNECTED:
		bufpos = bip_strcatf_fit(&remaining, bufpos,
					 "disconnected, attempts: %d, last: %s",
					 lnk->s_conn_attempt,
					 hrtime(lnk->last_connection_attempt));
		if (!bufpos)
			goto noroomstatus;
		break;
	case IRCS_RECONNECTING:
		bufpos = bip_strcatf_fit(
			&remaining, bufpos,
			"reconnecting... attempts: %d, last: %s",
			lnk->s_conn_attempt,
			hrtime(lnk->last_connection_attempt));
		if (!bufpos)
			goto noroomstatus;
		break;
	case IRCS_TIMER_WAIT:
		bufpos = bip_strcatf_fit(
			&remaining, bufpos,
			"waiting to reconnect, attempts: %d, last: %s",
			lnk->s_conn_attempt,
			hrtime(lnk->last_connection_attempt));
		if (!bufpos)
			goto noroomstatus;
		break;
	default:
		bufpos = bip_strcat_fit(&remaining, bufpos, "unknown");
		if (!bufpos)
			goto limittoolow;
		break;
		// s_conn_attempt recon_timer last_connection_attempt
	}
	buf[LINE_SIZE_LIM] = 0;
	bip_notify(ic, "%s", buf);
	return;
noroomstatus:
	buf[LINE_SIZE_LIM] = 0;
	bip_notify(ic, "%stoo long to print", buf);
	return;
limittoolow:
	bip_notify(ic,
		   "cannot print connection, LINE_SIZE_LIM(%d) "
		   "is too low (please recompile)",
		   LINE_SIZE_LIM);
	return;
}

void adm_list_all_links(struct link_client *ic)
{
	list_iterator_t it;

	bip_notify(ic, "-- All links");
	for (list_it_init(&_bip->link_list, &it); list_it_item(&it);
	     list_it_next(&it)) {
		struct link *l = list_it_item(&it);
		if (l)
			adm_print_connection(ic, l, NULL);
	}
	bip_notify(ic, "-- End of All links");
}

void adm_list_all_connections(struct link_client *ic)
{
	hash_iterator_t it;

	bip_notify(ic, "-- All connections");
	for (hash_it_init(&_bip->users, &it); hash_it_item(&it);
	     hash_it_next(&it)) {
		struct bipuser *u = hash_it_item(&it);
		if (u)
			adm_list_connections(ic, u);
	}
	bip_notify(ic, "-- End of All connections");
}

#define STRORNULL(s) ((s) == NULL ? "unset" : (s))

void adm_info_user(struct link_client *ic, const char *name)
{
	struct bipuser *u;

	bip_notify(ic, "-- User '%s' info", name);
	u = hash_get(&_bip->users, name);
	if (!u) {
		bip_notify(ic, "Unknown user");
		return;
	}

	bip_notify(ic, "user: %s%s", u->name,
		   (u->admin ? ", is bip admin" : ""));

#ifdef HAVE_LIBSSL
	if (u->ssl_check_store) {
		bip_notify(ic, "SSL check mode '%s', stored into '%s'",
			   checkmode2text(u->ssl_check_mode),
			   u->ssl_check_store);
	} else {
		bip_notify(
			ic,
			"SSL check mode '%s', default or no certificate store",
			checkmode2text(u->ssl_check_mode));
	}
	if (u->ssl_client_certfile)
		bip_notify(ic, "SSL client certificate stored into '%s'",
			   u->ssl_client_certfile);
#endif
	bip_notify(ic, "Defaults nick: %s, user: %s, realname: %s",
		   STRORNULL(u->default_nick), STRORNULL(u->default_username),
		   STRORNULL(u->default_realname));
	if (u->backlog) {
		bip_notify(ic,
			   "Backlog enabled, lines: %d, timestamp: %s,"
			   "  messages only: %s",
			   u->backlog_lines,
			   u->backlog_timestamp == BLTSNone
				   ? "none"
				   : (u->backlog_timestamp == BLTSTime
					      ? "time"
					      : "datetime"),
			   bool2text(u->bl_msg_only));
		bip_notify(ic, "always backlog: %s, reset on talk: %s",
			   bool2text(u->always_backlog),
			   bool2text(u->blreset_on_talk));
	} else {
		bip_notify(ic, "Backlog disabled");
	}
	adm_list_connections(ic, u);
	bip_notify(ic, "-- End of User '%s' info", name);
}

void adm_list_users(struct link_client *ic)
{
	hash_iterator_t it;
	hash_iterator_t lit;
	char buf[LINE_SIZE_LIM + 1];
	size_t remaining = LINE_SIZE_LIM;

	bip_notify(ic, "-- User list");
	for (hash_it_init(&_bip->users, &it); hash_it_item(&it);
	     hash_it_next(&it)) {
		struct bipuser *u = hash_it_item(&it);
		int first = 1;
		char *bufpos = buf;

		bufpos = bip_strcatf_fit(&remaining, bufpos, "* %s%s:", u->name,
					 (u->admin ? "(admin)" : ""));
		// this should not happen or LINE_SIZE_LIM is really low...
		if (!bufpos)
			goto limittoolow;
		for (hash_it_init(&u->connections, &lit); hash_it_item(&lit);) {
			struct link *lnk = hash_it_item(&lit);
			if (first) {
				first = 0;
			} else {
				bufpos =
					bip_strcat_fit(&remaining, bufpos, ",");
				// if this is too long for a comma, print and
				// prefix with spaces
				if (!bufpos) {
					buf[LINE_SIZE_LIM] = 0;
					bip_notify(ic, "%s", buf);
					remaining = LINE_SIZE_LIM;
					bufpos = bip_strcat_fit(&remaining, buf,
								"     ");
					;
					// this should not happen or
					// LINE_SIZE_LIM is really low...
					if (!bufpos)
						goto limittoolow;
				}
			}

			bufpos = bip_strcatf_fit(&remaining, bufpos, " %s",
						 lnk->name);
			if (!bufpos) {
				// if this is too long, print and reset
				buf[LINE_SIZE_LIM] = 0;
				bip_notify(ic, "%s", buf);
				remaining = LINE_SIZE_LIM;
				bufpos = bip_strcat_fit(&remaining, buf,
							"     ");
				;
				// this should not happen or LINE_SIZE_LIM is
				// really low...
				if (!bufpos)
					goto limittoolow;
			} else {
				// if all good, go to next entry
				hash_it_next(&lit);
			}
		}
		buf[LINE_SIZE_LIM] = 0;
		bip_notify(ic, "%s", buf);
		remaining = LINE_SIZE_LIM;
		bufpos = buf;
	}
	bip_notify(ic, "-- End of User list");
	return;
limittoolow:
	bip_notify(ic,
		   "cannot print users, LINE_SIZE_LIM(%d) "
		   "is too low (please recompile)",
		   LINE_SIZE_LIM);
}

void adm_list_networks(struct link_client *ic)
{
	hash_iterator_t it;
	char buf[RET_STR_LEN + 1];

	bip_notify(ic, "-- Network list (* means SSL):");
	for (hash_it_init(&_bip->networks, &it); hash_it_item(&it);
	     hash_it_next(&it)) {
		struct network *n = hash_it_item(&it);
		int i;
		char *bufpos = buf;
		size_t remaining = RET_STR_LEN;

#ifdef HAVE_LIBSSL
		if (n->ssl) {
			bufpos = bip_strcatf_fit(&remaining, bufpos,
						 "- %s*:", n->name);
		} else {
#endif
			bufpos = bip_strcatf_fit(&remaining, bufpos,
						 "- %s:", n->name);
#ifdef HAVE_LIBSSL
		}
#endif
		// if we've reached max length, print name and reset
		// honestly, this should not happen, but for the sake of
		// cleanliness...
		if (!bufpos) {
#ifdef HAVE_LIBSSL
			if (n->ssl) {
				bip_notify(ic, "- %s*:", n->name);
			} else {
#endif
				bip_notify(ic, "- %s:", n->name);
#ifdef HAVE_LIBSSL
			}
#endif
			bufpos = buf;
			remaining = RET_STR_LEN;
		}

		for (i = 0; i < n->serverc;) {
			struct server *serv = i + n->serverv;
			bufpos = bip_strcatf_fit(&remaining, bufpos, " %s:%d",
						 serv->host, serv->port);
			if (!bufpos) {
				// if line is too long, print and reset
				buf[RET_STR_LEN] = 0;
				bip_notify(ic, "%s", buf);
				remaining = RET_STR_LEN;
				bufpos = buf;
				i--;
			} else {
				// if ok, go to next server
				i++;
			}
		}
		buf[RET_STR_LEN] = 0;
		bip_notify(ic, "%s", buf);
	}
	bip_notify(ic, "-- End of Network list");
}

void adm_list_connections(struct link_client *ic, struct bipuser *bu)
{
	hash_iterator_t it;

	if (!bu) {
		bip_notify(ic, "-- Your connections:");
		bu = LINK(ic)->user;
	} else {
		bip_notify(ic, "-- User %s's connections:", bu->name);
	}

	for (hash_it_init(&bu->connections, &it); hash_it_item(&it);
	     hash_it_next(&it)) {
		struct link *lnk = hash_it_item(&it);
		adm_print_connection(ic, lnk, bu);
	}
	bip_notify(ic, "-- End of Connection list");
}

#ifdef HAVE_LIBSSL
int link_add_untrusted(struct link_server *ls, X509 *cert)
{
	int i;

	/* Check whether the cert is already in the stack */
	for (i = 0; i < sk_X509_num(LINK(ls)->untrusted_certs); i++) {
		if (!X509_cmp(cert,
			      sk_X509_value(LINK(ls)->untrusted_certs, i)))
			return 1;
	}

	return sk_X509_push(LINK(ls)->untrusted_certs, cert);
}

int ssl_check_trust(struct link_client *ic)
{
	X509 *trustcert = NULL;
	char subject[270];
	char issuer[270];
	unsigned char fp[EVP_MAX_MD_SIZE];
	char fpstr[EVP_MAX_MD_SIZE * 3 + 20];
	unsigned int fplen;
	int i;

	if (!LINK(ic)->untrusted_certs
	    || sk_X509_num(LINK(ic)->untrusted_certs) <= 0) {
		ic->allow_trust = 0;
		return 0;
	}

	trustcert = sk_X509_value(LINK(ic)->untrusted_certs, 0);
	strcpy(subject, "Subject: ");
	strcpy(issuer, "Issuer:  ");
	strcpy(fpstr, "MD5 fingerprint: ");
	X509_NAME_oneline(X509_get_subject_name(trustcert), subject + 9, 256);
	X509_NAME_oneline(X509_get_issuer_name(trustcert), issuer + 9, 256);

	X509_digest(trustcert, EVP_md5(), fp, &fplen);
	for (i = 0; i < (int)fplen; i++)
		sprintf(fpstr + 17 + (i * 3), "%02X%c", fp[i],
			(i == (int)fplen - 1) ? '\0' : ':');

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
		    "This server SSL certificate was not "
		    "accepted because it is not in your store "
		    "of trusted certificates:");

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm", subject);
	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm", issuer);
	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm", fpstr);

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
		    "WARNING: if you've already trusted a "
		    "certificate for this server before, that "
		    "probably means it has changed.");

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
		    "If so, YOU MAY BE SUBJECT OF A "
		    "MAN-IN-THE-MIDDLE ATTACK! PLEASE DON'T TRUST "
		    "THIS CERTIFICATE IF YOU'RE NOT SURE THIS IS "
		    "NOT THE CASE.");

	WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
		    "Type /QUOTE BIP TRUST OK to trust this "
		    "certificate, /QUOTE BIP TRUST NO to discard it.");

	TYPE(ic) = IRC_TYPE_TRUST_CLIENT;
	ic->allow_trust = 1;
	return 1;
}

#if 0
static int ssl_trust_next_cert(struct link_client *ic)
{
	(void)ic;
}

static int ssl_discard_next_cert(struct link_client *ic)
{
	(void)ic;
}
#endif /* 0 */
#endif

#ifdef HAVE_LIBSSL
int adm_trust(struct link_client *ic, struct line *line)
{
	if (ic->allow_trust != 1) {
		/* shouldn't have been asked to /QUOTE BIP TRUST but well... */
		WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", "TrustEm",
			    "No untrusted certificates.");
		return OK_FORGET;
	}

	if (irc_line_count(line) != 3)
		return ERR_PROTOCOL;

	if (irc_line_elem_case_equals(line, 2, "OK")) {
		/* OK, attempt to trust the cert! */
		BIO *bio = BIO_new_file(LINK(ic)->user->ssl_check_store, "a+");
		X509 *trustcert = sk_X509_shift(LINK(ic)->untrusted_certs);

		if (!bio || !trustcert
		    || PEM_write_bio_X509(bio, trustcert) <= 0)
			write_line_fast(CONN(ic),
					":irc.bip.net NOTICE pouet "
					":==== Error while trusting test!\r\n");
		else
			write_line_fast(CONN(ic),
					":irc.bip.net NOTICE pouet "
					":==== Certificate now trusted.\r\n");

		BIO_free_all(bio);
		X509_free(trustcert);
	} else if (irc_line_elem_case_equals(line, 2, "NO")) {
		/* NO, discard the cert! */
		write_line_fast(CONN(ic),
				":irc.bip.net NOTICE pouet "
				":==== Certificate discarded.\r\n");

		X509_free(sk_X509_shift(LINK(ic)->untrusted_certs));
	} else
		return ERR_PROTOCOL;

	if (!ssl_check_trust(ic)) {
		write_line_fast(CONN(ic),
				":irc.bip.net NOTICE pouet "
				":No more certificates waiting awaiting "
				"user trust, thanks!\r\n");
		write_line_fast(CONN(ic),
				":irc.bip.net NOTICE pouet "
				":If the certificate is trusted, bip should "
				"be able to connect to the server on the "
				"next retry. Please wait a while and try "
				"connecting your client again.\r\n");

		LINK(ic)->recon_timer = 1; /* Speed up reconnection... */
		return OK_CLOSE;
	}
	return OK_FORGET;
}
#endif

void _bip_notify(struct link_client *ic, char *fmt, va_list ap)
{
	char *nick;
	char str[4096];

	if (LINK(ic)->l_server)
		nick = LINK(ic)->l_server->nick;
	else
		nick = LINK(ic)->prev_nick;

	vsnprintf(str, (size_t)4095, fmt, ap);
	str[4095] = 0;
	WRITE_LINE2(CONN(ic), P_IRCMASK,
		    (LINK(ic)->user->bip_use_notice ? "NOTICE" : "PRIVMSG"),
		    nick, str);
}

void bip_notify(struct link_client *ic, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	_bip_notify(ic, fmt, ap);
	va_end(ap);
}

void adm_blreset(struct link_client *ic)
{
	log_reset_all(LINK(ic)->log);
	bip_notify(ic, "backlog reset for this network.");
}

void adm_blreset_store(struct link_client *ic, const char *store)
{
	log_reset_store(LINK(ic)->log, store);
	bip_notify(ic, "backlog reset for %s.", store);
}

void adm_follow_nick(struct link_client *ic, const char *val)
{
	struct link *link = LINK(ic);
	if (strcasecmp(val, "TRUE") == 0) {
		link->follow_nick = 1;
		bip_notify(ic, "follow_nick is now true.");
	} else {
		link->follow_nick = 0;
		bip_notify(ic, "follow_nick is now false.");
	}
}

void adm_ignore_first_nick(struct link_client *ic, const char *val)
{
	struct link *link = LINK(ic);
	if (strcasecmp(val, "TRUE") == 0) {
		link->ignore_first_nick = 1;
		bip_notify(ic, "ignore_first_nick is now true.");
	} else {
		link->ignore_first_nick = 0;
		bip_notify(ic, "ignore_first_nick is now false.");
	}
}

void set_on_connect_send(struct link_client *ic, char *val)
{
	struct link *link = LINK(ic);
	char *s;

	if (val != NULL) {
		list_add_last(&link->on_connect_send, bip_strdup(val));
		bip_notify(ic, "added to on_connect_send.");
	} else {
		s = list_remove_last(&link->on_connect_send);
		if (s)
			free(s);
		bip_notify(ic, "last on_connect_send string deleted.");
	}
}

#define ON_CONNECT_MAX_STRSIZE 1024
void adm_on_connect_send(struct link_client *ic, struct line *line, int privmsg)
{
	size_t remaining = ON_CONNECT_MAX_STRSIZE;
	char buf[ON_CONNECT_MAX_STRSIZE];
	char *bufpos = buf;
	int i;

	if (!line) {
		set_on_connect_send(ic, NULL);
		return;
	}

	if (!irc_line_includes(line, 2)) {
		mylog(LOG_DEBUG,
		      "[%s] not enough parameters on /BIP on_connect_send",
		      LINK(ic)->user->name);
		return;
	}

	for (i = privmsg + 2; i < irc_line_count(line); i++) {
		mylog(LOG_DEBUG, "[%s] processing item %d, remaining %ld, %s",
		      LINK(ic)->user->name, i, remaining, buf);
		if (i > privmsg + 2)
			bufpos = bip_strcatf_fit(&remaining, bufpos, " %s",
						 irc_line_elem(line, i));
		else
			bufpos = bip_strcat_fit(&remaining, bufpos,
						irc_line_elem(line, i));
		mylog(LOG_DEBUG, "[%s] processed item %d, remaining %ld, %s",
		      LINK(ic)->user->name, i, remaining, buf);
		if (!bufpos) {
			bip_notify(
				ic,
				"on connect send string too big, not changing.");
			return;
		}
	}

	buf[ON_CONNECT_MAX_STRSIZE - 1] = 0;
	set_on_connect_send(ic, buf);
	return;
}

void adm_away_nick(struct link_client *ic, const char *val)
{
	struct link *link = LINK(ic);
	if (link->away_nick) {
		free(link->away_nick);
		link->away_nick = NULL;
	}
	if (val != NULL) {
		link->away_nick = bip_strdup(val);
		bip_notify(ic, "away_nick set.");
	} else {
		bip_notify(ic, "away_nick cleared.");
	}
}

void adm_bip_help(struct link_client *ic, int admin, const char *subhelp)
{
	if (subhelp == NULL) {
		if (admin) {
			bip_notify(ic,
				   "/BIP RELOAD # Re-read bip "
				   "configuration and apply changes.");
			bip_notify(ic,
				   "/BIP INFO user <username> "
				   "# show a user's configuration");
			bip_notify(ic,
				   "/BIP LIST networks|users|connections|"
				   "all_links|all_connections");
			bip_notify(ic,
				   "/BIP ADD_CONN <connection name> "
				   "<network>");
			bip_notify(ic, "/BIP DEL_CONN <connection name>");
		} else {
			bip_notify(ic, "/BIP LIST networks|connections");
		}
		bip_notify(ic,
			   "/BIP JUMP # jump to next server (in same "
			   "network)");
		bip_notify(ic,
			   "/BIP BLRESET [channel|query]# reset backlog "
			   "(this connection only). Add -q flag and the "
			   "operation is quiet. You can specify a channel "
			   "or a nick to reset only this channel/query.");
		bip_notify(ic, "/BIP HELP [subhelp] # show this help...");
		bip_notify(ic, "## Temporary changes for this connection:");
		bip_notify(ic, "/BIP FOLLOW_NICK|IGNORE_FIRST_NICK TRUE|FALSE");
		bip_notify(ic,
			   "/BIP ON_CONNECT_SEND <str> # Adds a string to "
			   "send on connect");
		bip_notify(ic, "/BIP ON_CONNECT_SEND # Clears on_connect_send");
		bip_notify(ic, "/BIP AWAY_NICK <nick> # Set away nick");
		bip_notify(ic, "/BIP AWAY_NICK # clear away nick");
		bip_notify(ic,
			   "/BIP BACKLOG [n] # backlog text of the n last "
			   "hours");
	} else if (admin && strcasecmp(subhelp, "RELOAD") == 0) {
		bip_notify(ic, "/BIP RELOAD (admin only) :");
		bip_notify(ic,
			   "  Reloads bip configuration file and apply "
			   "changes.");
		bip_notify(ic,
			   "  Please note that changes to 'user' or "
			   "'realname' will not be applied without a JUMP.");
	} else if (admin && strcasecmp(subhelp, "INFO") == 0) {
		bip_notify(ic, "/BIP INFO USER <user> (admin only) :");
		bip_notify(ic, "  Show <user>'s current configuration.");
		bip_notify(ic,
			   "  That means it may be different from the "
			   "configuration stored in bip.conf");
	} else if (admin && strcasecmp(subhelp, "ADD_CONN") == 0) {
		bip_notify(ic,
			   "/BIP ADD_CONN <connection name> <network> "
			   "(admin only) :");
		bip_notify(ic,
			   "  Add a connection named <connection name> to "
			   "the network <network> to your connection list");
		bip_notify(ic,
			   "  <network> should already exist in bip's "
			   "configuration.");
	} else if (admin && strcasecmp(subhelp, "DEL_CONN") == 0) {
		bip_notify(ic,
			   "/BIP DEL_CONN <connection name> (admin only) "
			   ":");
		bip_notify(ic,
			   "  Remove the connection named <connection "
			   "name> from your connection list.");
		bip_notify(ic,
			   "  Removing a connection will cause "
			   "its disconnection.");
	} else if (strcasecmp(subhelp, "JUMP") == 0) {
		bip_notify(ic, "/BIP JUMP :");
		bip_notify(ic, "  Jump to next server in current network.");
	} else if (strcasecmp(subhelp, "BLRESET") == 0) {
		bip_notify(ic, "/BIP BLRESET :");
		bip_notify(ic, "  Reset backlog on this network.");
	} else if (strcasecmp(subhelp, "FOLLOW_NICK") == 0) {
		bip_notify(ic, "/BIP FOLLOW_NICK TRUE|FALSE :");
		bip_notify(ic,
			   "  Change the value of the follow_nick option "
			   "for this connection.");
		bip_notify(ic,
			   "  If set to true, when you change nick, "
			   "BIP stores the new nickname as the new default "
			   "nickname value.");
		bip_notify(ic,
			   "  Thus, if you are disconnected from the "
			   "server, BIP will restore the correct nickname.");
	} else if (strcasecmp(subhelp, "IGNORE_FIRST_NICK") == 0) {
		bip_notify(ic, "/BIP IGNORE_FIRST_NICK TRUE|FALSE :");
		bip_notify(ic,
			   "  Change the value of the ignore_first_nick "
			   "option for this connection.");
		bip_notify(ic,
			   "  If set to TRUE, BIP will ignore the nickname"
			   "sent by the client upon connect.");
		bip_notify(ic,
			   "  Further nickname changes will be processed "
			   "as usual.");
	} else if (strcasecmp(subhelp, "ON_CONNECT_SEND") == 0) {
		bip_notify(ic, "/BIP ON_CONNECT_SEND [some text] :");
		bip_notify(ic,
			   "  BIP will send the text as is to the server "
			   "upon connection.");
		bip_notify(ic, "  You can call this command more than once.");
		bip_notify(
			ic,
			"  If [some text] is empty, this command will "
			"remove any on_connect_send defined for this connection.");
	} else if (strcasecmp(subhelp, "AWAY_NICK") == 0) {
		bip_notify(ic, "/BIP AWAY_NICK [some_nick] :");
		bip_notify(
			ic,
			"  If [some_nick] is set, BIP will change "
			"nickname to [some_nick] if there are no more client "
			"attached");
		bip_notify(ic,
			   "  If [some_nick] is empty, this command will "
			   "unset current connection's away_nick.");
	} else if (strcasecmp(subhelp, "LIST") == 0) {
		bip_notify(ic, "/BIP LIST <section> :");
		bip_notify(ic, "  List information from a these sections :");
		bip_notify(ic, "  - networks: list all available networks");
		bip_notify(ic,
			   "  - connections: list all your configured "
			   "connections and their state.");
		if (admin) {
			bip_notify(ic, "  - users: list all users (admin)");
			bip_notify(ic,
				   "  - all_links: list all connected "
				   "sockets from and to BIP (admin)");
			bip_notify(ic,
				   "  - all_connections: list all users' "
				   "configured connections (admin)");
		}
	} else {
		bip_notify(ic, "-- No sub-help for '%s'", subhelp);
	}
}

int adm_bip(bip_t *bip, struct link_client *ic, struct line *line, int privmsg)
{
	int admin = LINK(ic)->user->admin;

	if (privmsg) {
		char *linestr, *elemstr;
		char *ptr, *eptr;
		size_t slen;

		if (irc_line_count(line) != 3)
			return OK_FORGET;

		linestr = irc_line_pop(line);
		ptr = linestr;

		/* all elem size <= linestr size */
		elemstr = bip_malloc(strlen(linestr) + 1);

		while ((eptr = strstr(ptr, " "))) {
			// eptr is either >= ptr or NULL from strstr()
			// but it can't be NULL per while loop
			// we can then assume slen is unsigned
			slen = (size_t)(eptr - ptr);
			if (slen == 0) {
				ptr++;
				continue;
			}
			memcpy(elemstr, ptr, slen);
			elemstr[slen] = 0;
			irc_line_append(line, elemstr);
			ptr = eptr + 1;
		}
		slen = strlen(ptr);
		eptr = ptr + slen;
		if (slen != 0) {
			memcpy(elemstr, ptr, slen);
			elemstr[slen] = 0;
			irc_line_append(line, elemstr);
		}
		free(elemstr);
		free(linestr);
	}

	if (!irc_line_includes(line, privmsg + 1))
		return OK_FORGET;

	mylog(LOG_INFO, "/BIP %s from %s", irc_line_elem(line, privmsg + 1),
	      LINK(ic)->user->name);
	if (irc_line_elem_case_equals(line, privmsg + 1, "RELOAD")) {
		if (!admin) {
			bip_notify(ic, "-- You're not allowed to reload bip");
			return OK_FORGET;
		}
		bip_notify(ic, "-- Reloading bip...");
		bip->reloading_client = ic;
		sighup = 1;
	} else if (irc_line_elem_case_equals(line, privmsg + 1, "LIST")) {
		if (irc_line_count(line) != privmsg + 3) {
			bip_notify(ic, "-- LIST command needs one argument");
			return OK_FORGET;
		}

		if (admin
		    && strcasecmp(irc_line_elem(line, privmsg + 2), "users")
			       == 0) {
			adm_list_users(ic);
		} else if (strcasecmp(irc_line_elem(line, privmsg + 2),
				      "networks")
			   == 0) {
			adm_list_networks(ic);
		} else if (strcasecmp(irc_line_elem(line, privmsg + 2),
				      "connections")
			   == 0) {
			adm_list_connections(ic, NULL);
		} else if (admin
			   && strcasecmp(irc_line_elem(line, privmsg + 2),
					 "all_connections")
				      == 0) {
			adm_list_all_connections(ic);
		} else if (admin
			   && strcasecmp(irc_line_elem(line, privmsg + 2),
					 "all_links")
				      == 0) {
			adm_list_all_links(ic);
		} else {
			bip_notify(ic, "-- Invalid LIST request");
		}
	} else if (irc_line_elem_case_equals(line, privmsg + 1, "INFO")) {
		if (!irc_line_includes(line, privmsg + 3)) {
			bip_notify(ic,
				   "-- INFO command needs at least two "
				   "arguments");
			return OK_FORGET;
		}

		if (admin
		    && irc_line_elem_case_equals(line, privmsg + 2, "user")) {
			if (irc_line_count(line) == (privmsg + 4)) {
				adm_info_user(ic,
					      irc_line_elem(line, privmsg + 3));
			} else {
				bip_notify(ic,
					   "-- INFO USER command needs one"
					   " argument");
			}
#if 0
			TODO network info
#endif
		} else {
			bip_notify(ic, "-- Invalid INFO request");
		}
	} else if (irc_line_elem_case_equals(line, privmsg + 1, "JUMP")) {
		if (LINK(ic)->l_server) {
			WRITE_LINE1(CONN(LINK(ic)->l_server), NULL, "QUIT",
				    "jumpin' jumpin'");
			connection_close(CONN(LINK(ic)->l_server));
		}
		bip_notify(ic, "-- Jumping to next server");
	} else if (irc_line_elem_case_equals(line, privmsg + 1, "BLRESET")) {
		if (irc_line_includes(line, privmsg + 2)) {
			if (irc_line_elem_equals(line, privmsg + 2, "-q")) {
				if (irc_line_includes(line, privmsg + 3)) {
					log_reset_store(
						LINK(ic)->log,
						irc_line_elem(line,
							      privmsg + 3));
				} else {
					log_reset_all(LINK(ic)->log);
				}
			} else {
				adm_blreset_store(
					ic, irc_line_elem(line, privmsg + 2));
			}
		} else {
			adm_blreset(ic);
		}
	} else if (irc_line_elem_case_equals(line, privmsg + 1, "HELP")) {
		if (irc_line_count(line) == privmsg + 2)
			adm_bip_help(ic, admin, NULL);
		else if (irc_line_count(line) == privmsg + 3)
			adm_bip_help(ic, admin,
				     irc_line_elem(line, privmsg + 2));
		else
			bip_notify(
				ic,
				"-- HELP command needs at most one argument");
	} else if (irc_line_elem_case_equals(line, privmsg + 1,
					     "FOLLOW_NICK")) {
		if (irc_line_count(line) != privmsg + 3) {
			bip_notify(ic,
				   "-- FOLLOW_NICK command needs one argument");
			return OK_FORGET;
		}
		adm_follow_nick(ic, irc_line_elem(line, privmsg + 2));
	} else if (irc_line_elem_case_equals(line, privmsg + 1,
					     "IGNORE_FIRST_NICK")) {
		if (irc_line_count(line) != privmsg + 3) {
			bip_notify(ic,
				   "-- IGNORE_FIRST_NICK "
				   "command needs one argument");
			return OK_FORGET;
		}
		adm_ignore_first_nick(ic, irc_line_elem(line, privmsg + 2));
	} else if (irc_line_elem_case_equals(line, privmsg + 1,
					     "ON_CONNECT_SEND")) {
		if (irc_line_count(line) == privmsg + 2) {
			adm_on_connect_send(ic, NULL, 0);
		} else if (irc_line_includes(line, privmsg + 2)) {
			adm_on_connect_send(ic, line, privmsg);
		} else {
			bip_notify(ic,
				   "-- ON_CONNECT_SEND command needs at "
				   "least one argument");
		}
	} else if (irc_line_elem_case_equals(line, privmsg + 1, "AWAY_NICK")) {
		if (irc_line_count(line) == privmsg + 2) {
			adm_away_nick(ic, NULL);
		} else if (irc_line_count(line) == privmsg + 3) {
			adm_away_nick(ic, irc_line_elem(line, privmsg + 2));
		} else {
			bip_notify(ic,
				   "-- AWAY_NICK command needs zero or one"
				   " argument");
		}
	} else if (irc_line_elem_case_equals(line, privmsg + 1, "BACKLOG")) {
		if (irc_line_count(line) == privmsg + 2) {
			irc_cli_backlog(ic, 0);
		} else if (irc_line_count(line) == privmsg + 3) {
			int hours = atoi(irc_line_elem(line, privmsg + 2));
			irc_cli_backlog(ic, hours);
		} else {
			bip_notify(ic, "-- BACKLOG takes 0 or one argument");
		}
	} else if (admin
		   && irc_line_elem_case_equals(line, privmsg + 1,
						"ADD_CONN")) {
		if (irc_line_count(line) != privmsg + 4) {
			bip_notify(ic,
				   "/BIP ADD_CONN <connection name> "
				   "<network name>");
		} else {
			adm_bip_addconn(bip, ic,
					irc_line_elem(line, privmsg + 2),
					irc_line_elem(line, privmsg + 3));
		}
	} else if (admin
		   && irc_line_elem_case_equals(line, privmsg + 1,
						"DEL_CONN")) {
		if (irc_line_count(line) != privmsg + 3) {
			bip_notify(ic, "/BIP DEL_CONN <connection name>");
		} else {
			adm_bip_delconn(bip, ic,
					irc_line_elem(line, privmsg + 2));
		}
#ifdef HAVE_LIBSSL
	} else if (strcasecmp(irc_line_elem(line, privmsg + 1), "TRUST") == 0) {
		return adm_trust(ic, line);
#endif
	} else {
		bip_notify(ic, "Unknown command.");
	}
	return OK_FORGET;
}

void free_conf(list_t *l)
{
	struct tuple *t;
	list_iterator_t li;

	for (list_it_init(l, &li); (t = list_it_item(&li)); list_it_next(&li)) {
		switch (t->tuple_type) {
		case TUPLE_STR:
			free(t->pdata);
			break;
		case TUPLE_INT:
			break;
		case TUPLE_LIST:
			free_conf(t->pdata);
			break;
		default:
			fatal("internal error free_conf");
			break;
		}
		free(t);
	}
	free(l);
}
