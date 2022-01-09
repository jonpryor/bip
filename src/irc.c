/*
 * $Id: irc.c,v 1.156 2005/04/21 06:58:50 nohar Exp $
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
#include <string.h>
#include <stdio.h>
#include "util.h"
#include "irc.h"
#include "bip.h"
#include "log.h"
#include "connection.h"
#include "md5.h"
#include "utils/base64.h"

#define S_CONN_DELAY (10)

extern int sighup;
extern bip_t *_bip;

static int irc_join(struct link_server *server, struct line *line);
static int irc_part(struct link_server *server, struct line *line);
static int irc_mode(struct link_server *server, struct line *line);
static int irc_mode_channel(struct link_server *s, struct channel *channel,
				struct line *line, const char* mode, int add, int cur_arg);
static int irc_kick(struct link_server *server, struct line *line);
static int irc_privmsg(struct link_server *server, struct line *line);
static int irc_notice(struct link_server *server, struct line *line);
static int irc_quit(struct link_server *server, struct line *line);
static int irc_nick(struct link_server *server, struct line *line);
static int irc_generic_quit(struct link_server *server, struct line *line);
static int irc_topic(struct link_server *server, struct line *line);
static int irc_332(struct link_server *server, struct line *line);
static int irc_333(struct link_server *server, struct line *line);
static int irc_353(struct link_server *server, struct line *line);
static int irc_366(struct link_server *server, struct line *line);
static int irc_367(struct link_server *server, struct line *l);
static int irc_368(struct link_server *server, struct line *l);
void irc_server_shutdown(struct link_server *s);
static int origin_is_me(struct line *l, struct link_server *server);
static void ls_set_nick(struct link_server *ircs, char *nick);
static void server_set_chanmodes(struct link_server *l, const char *chanmodes);
static void server_set_prefix(struct link_server *l, const char *prefix);
static void server_init_modes(struct link_server *s);
static int bip_get_index(const char* str, char car);
static int bip_fls(int v);

void oidentd_dump(bip_t *bip);

void irc_client_free(struct link_client *cli);
extern int conf_log_sync_interval;
extern int conf_reconn_timer;

void write_user_list(connection_t *c, char *dest);

static void irc_copy_cli(struct link_client *src, struct link_client *dest,
		struct line *line);
static void irc_cli_make_join(struct link_client *ic);
static void server_setup_reconnect_timer(struct link *link);
int irc_cli_bip(bip_t *bip, struct link_client *ic, struct line *line);
static int irc_server_sasl_authenticate(struct link_server *ircs);
static char *sasl_mechanism_to_text(int sasl_mechanism);

#define LAGOUT_TIME 480
#define LAGCHECK_TIME (90)
#define RECONN_TIMER_MAX (600)
#define LOGGING_TIMEOUT (360)
#define CONN_INTERVAL 60
#define CONNECT_TIMEOUT 60

struct channel *channel_new(const char *name)
{
	struct channel *chan;
	chan = bip_calloc(sizeof(struct channel), (size_t)1);
	chan->name = bip_strdup(name);
	hash_init(&chan->ovmasks, HASH_NOCASE);
	return chan;
}

char *nick_from_ircmask(const char *mask)
{
	const char *nick = mask;
	char *ret;
	size_t len;

	assert(mask);

	while (*nick && *nick != '!')
		nick++;
	if (!*nick)
		return bip_strdup(mask);
	len = nick - mask;
	ret = bip_malloc(len + 1);
	memcpy(ret, mask, len);
	ret[len] = 0;
	return ret;
}

#define NAMESIZE 256

list_t *channel_name_list(struct link_server *server, struct channel *c)
{
	list_t *ret;
	hash_iterator_t hi;
	size_t len = 0;
	char *str = bip_malloc((size_t)(NAMESIZE + 1));

	ret = list_new(NULL);
	*str = 0;
	for (hash_it_init(&c->ovmasks, &hi); hash_it_key(&hi);
			hash_it_next(&hi)){
		const char *nick = hash_it_key(&hi);
		long int ovmask = (long int)hash_it_item(&hi);

		assert(strlen(nick) + 2 < NAMESIZE);

		if (len + strlen(nick) + 2 + (ovmask ? 1 : 0) >= NAMESIZE) {
			list_add_last(ret, str);
			str = bip_malloc((size_t)(NAMESIZE + 1));
			*str = 0;
			len = 0;
		}
		if (len != 0) {
			strcat(str, " ");
			len++;
		}

		// prepend symbol corresponding to the usermode
		int msb;
		if ((msb = bip_fls(ovmask))) {
			str[len] = server->prefixes[msb - 1];
			str[++len] = 0;
		}

		strcat(str, nick);
		len += strlen(nick);
		assert(len < NAMESIZE);
	}
	list_add_last(ret, str);
	return ret;
}

char *link_name(struct link_any *l)
{
	if (LINK(l))
		return LINK(l)->name ? LINK(l)->name : "(null)";
	return "*connecting*";
}

static int irc_001(struct link_server *server, struct line *line)
{
	(void)line;

	if (LINK(server)->s_state == IRCS_WAS_CONNECTED)
		LINK(server)->s_state = IRCS_RECONNECTING;
	else
		LINK(server)->s_state = IRCS_CONNECTING;

	/* change nick on client */
	int i;
	for (i = 0; i < LINK(server)->l_clientc; i++) {
		struct link_client *c = LINK(server)->l_clientv[i];
		WRITE_LINE1(CONN(c), LINK(server)->cli_nick, "NICK",
				server->nick);
	}
	return OK_COPY;
}

void irc_start_lagtest(struct link_server *l)
{
	l->laginit_ts = time(NULL);
	write_line_fast(CONN(l), "PING :" S_PING "\r\n");
}

/*
 * returns 0 if we ping timeout
 */
void irc_compute_lag(struct link_server *is)
{
	assert(is->laginit_ts != -1);
	is->lag = time(NULL) - is->laginit_ts;
}

int irc_lags_out(struct link_server *is)
{
	if (is->lag > LAGOUT_TIME) {
		mylog(LOG_ERROR, "[%s] Lags out! closing", LINK(is)->name);
		return 1;
	} else {
		mylog(LOG_DEBUG, "[%s] lag : %d\n", LINK(is)->name, is->lag);
		return 0;
	}
}

void irc_lag_init(struct link_server *is)
{
	is->lagtest_timeout = LAGCHECK_TIME;
	is->laginit_ts = -1;
}

static void irc_server_join(struct link_server *s)
{
	list_iterator_t it;
	for (list_it_init(&LINK(s)->chan_infos_order, &it); list_it_item(&it);
			list_it_next(&it)) {
		struct chan_info *ci = list_it_item(&it);
		if (!ci->key)
			WRITE_LINE1(CONN(s), NULL, "JOIN", ci->name);
		else
			WRITE_LINE2(CONN(s), NULL, "JOIN", ci->name, ci->key);
	}
}

static void irc_server_connected(struct link_server *server)
{
	int i;

        LINK(server)->s_state = IRCS_CONNECTED;
        LINK(server)->s_conn_attempt = 0;

	mylog(LOG_INFO, "[%s] Connected for user %s",
			LINK(server)->name, LINK(server)->user->name);

        irc_server_join(server);
        log_connected(LINK(server)->log);

	if (LINK(server)->cli_nick) {
		/* we change nick on client */
		for (i = 0; i < LINK(server)->l_clientc; i++) {
			struct link_client *ic = LINK(server)->l_clientv[i];
			WRITE_LINE1(CONN(ic), LINK(server)->cli_nick, "NICK",
					server->nick);
		}
		free(LINK(server)->cli_nick);
		LINK(server)->cli_nick = NULL;
	}

	/* basic helper for nickserv and co */
	list_iterator_t itocs;
	for (list_it_init(&LINK(server)->on_connect_send, &itocs);
				list_it_item(&itocs); list_it_next(&itocs)) {
		size_t len = strlen(list_it_item(&itocs)) + 2;
		char *str = bip_malloc(len + 1);
		sprintf(str, "%s\r\n", (char *)list_it_item(&itocs));
		write_line(CONN(server), str);
		free(str);
        }

	if (LINK(server)->l_clientc == 0) {
		if (LINK(server)->away_nick)
			WRITE_LINE1(CONN(server), NULL, "NICK",
					LINK(server)->away_nick);
		if (LINK(server)->no_client_away_msg)
			WRITE_LINE1(CONN(server), NULL, "AWAY",
					LINK(server)->no_client_away_msg);
	}
}

/*
 * Given the way irc nets disrespect the rfc, we completely forget
 * about this damn ircmask...
:irc.iiens.net 352 pwet * ~a je.suis.t1r.net irc.iiens.net pwet H :0 d
-> nohar!~nohar@haruka.t1r.net
*/
static int irc_352(struct link_server *server, struct line *line)
{
	(void)server;
	if (!irc_line_includes(line, 6))
		return ERR_PROTOCOL;

#if 0
	if (irc_line_elem_case_equals(line, 6, server->nick)) {
		const char *nick = server->nick;
		const char *iname = irc_line_elem(line, 3);
		const char *ihost = irc_line_elem(line, 4);
		char *ircmask = bip_malloc(strlen(nick) + strlen(iname) +
				strlen(ihost) + 3);
		strcpy(ircmask, nick);
		strcat(ircmask, "!");
		strcat(ircmask, iname);
		strcat(ircmask, "@");
		strcat(ircmask, ihost);
		if (server->ircmask)
			free(server->ircmask);
		server->ircmask = ircmask;
	}
#endif

#if 0
	if (!origin_is_me(line, server)) {
		struct channel *channel;
		struct nick *nick;

		channel = hash_get(&server->channels, irc_line_elem(line, 2));
		if (!channel)
			return OK_COPY_WHO;

		nick = hash_get(&channel->nicks, irc_line_elem(line, 6));
		if (!nick)
			return OK_COPY_WHO;
	}

#endif
	return OK_COPY_WHO;
}

static int irc_315(struct link_server *server, struct line *l)
{
	(void)l;
	struct link *link = LINK(server);
	if (link->who_client) {
		if (link->who_client->who_count == 0) {
			mylog(LOG_DEBUG, "Spurious irc_315");
			return OK_COPY_WHO;
		}
		link->who_client->whoc_tstamp = time(NULL);
		if (link->who_client->who_count > 0) {
			--link->who_client->who_count;
			mylog(LOG_DEBUG,
				"RPL_ENDOFWHO: "
				"Decrementing who count for %p: %d",
				link->who_client, link->who_client->who_count);
		}
	}

	return OK_COPY_WHO;
}

void rotate_who_client(struct link *link)
{
	int i;
	mylog(LOG_DEBUG, "rotate_who_client %p", link->who_client);
	/* find a client with non-null who_count */
	link->who_client = NULL;
	for (i = 0; i < link->l_clientc; i++) {
		struct link_client *ic = link->l_clientv[i];
		if (!list_is_empty(&ic->who_queue)) {
			char *l;
			while ((l = list_remove_first(&ic->who_queue))) {
				write_line(CONN(link->l_server), l);
				free(l);
			}
			link->who_client = ic;
			break;
		}
	}
}

int irc_dispatch_server(bip_t *bip, struct link_server *server,
		struct line *line)
{
	int ret = OK_COPY;
	/* shut gcc up */
	(void)bip;

	if (!irc_line_includes(line, 0))
		return ERR_PROTOCOL;

	if (irc_line_elem_equals(line, 0, "PING")) {
		if (!irc_line_includes(line, 1))
			return ERR_PROTOCOL;
		struct line *resp = irc_line_new();
		char *resps;
		irc_line_append(resp, "PONG");
		irc_line_append(resp, irc_line_elem(line, 1));
		resp->colon = 1; /* it seems some ircds want it */
		resps = irc_line_to_string(resp);
		write_line_fast(CONN(server), resps);
		irc_line_free(resp);
		free(resps);
		ret = OK_FORGET;
	} else if (irc_line_elem_equals(line, 0, "PONG")) {
		/* not all server reply with PONG <servername> <our string>
		 * so we blindly assume the PONG is ours. */
		if (irc_line_count(line) == 2 || irc_line_count(line) == 3) {
			if (server->laginit_ts != -1) {
				irc_compute_lag(server);
				irc_lag_init(server);
			}
			ret = OK_FORGET;
		}
	} else if (irc_line_elem_equals(line, 0, "CAP")) {
		if (LINK(server)->sasl_mechanism) {
			if (irc_line_elem_equals(line, 2, "ACK") && irc_line_elem_equals(line, 3, "sasl")) {
				// Server is answering our CAP REQ :sasl and is SASL capable
				char *sasl_mech = sasl_mechanism_to_text(LINK(server)->sasl_mechanism);
				mylog(LOG_INFO, "[%s] Server is SASL capable, starting %s authentication.",
					LINK(server)->name, sasl_mech);
				WRITE_LINE1(CONN(server), NULL, "AUTHENTICATE", sasl_mech);
				ret = OK_FORGET;
			} else if (irc_line_elem_equals(line, 2, "NAK") && irc_line_elem_equals(line, 3, "sasl")) {
				// Server is answering our CAP REQ :sasl and isn't SASL capable
				mylog(LOG_INFO, "[%s] Server is not SASL capable.", LINK(server)->name);
				ret = ERR_PROTOCOL;
			} else {
				// Unhandled CAP message
				mylog(LOG_ERROR, "[%s] Unhandled CAP message: %s",
						LINK(server)->name, irc_line_to_string(line));
				ret = OK_FORGET;
			}
		} else {
			// Unhandled CAP message
			mylog(LOG_ERROR, "[%s] Unhandled CAP message: %s", LINK(server)->name,
					irc_line_to_string(line));
			ret = OK_FORGET;
		}
	} else if (irc_line_elem_equals(line, 0, "AUTHENTICATE")) {
		if (LINK(server)->sasl_mechanism) {
			if (irc_line_count(line) == 2 && irc_line_elem_equals(line, 1, "+")) {
				// Server is waiting for us to authenticate, let's do it
				mylog(LOG_INFO, "[%s] Server accepted our authentication mechanism.",
						LINK(server)->name);
				ret = irc_server_sasl_authenticate(server);
			} else {
				// Anything else than "AUTHENTICATE +" is unknown to us
				mylog(LOG_ERROR, "[%s] Server sent gibberish: %s",
						LINK(server)->name, irc_line_to_string(line));
				ret = ERR_PROTOCOL;
			}
		} else {
			// Unhandled AUTHENTICATE message
			mylog(LOG_ERROR, "[%s] Unhandled AUTHENTICATE message: %s",
					LINK(server)->name, irc_line_to_string(line));
			ret = OK_FORGET;
		}
	} else if (irc_line_elem_equals(line, 0, "900")) {
		if (irc_line_count(line) >= 5) {
			mylog(LOG_INFO, "[%s] Logged in as %s(%s): %s", LINK(server)->name,
				irc_line_elem(line, 3), irc_line_elem(line, 2), irc_line_elem(line, 4));
		} else {
			mylog(LOG_INFO, "[%s] Logged in: %s", LINK(server)->name, irc_line_to_string(line));
		}
		ret = OK_FORGET;
	} else if (irc_line_elem_equals(line, 0, "901")) {
		if (irc_line_count(line) >= 4) {
			mylog(LOG_INFO, "[%s] Logged out: %s",
				LINK(server)->name, irc_line_elem(line, 3));
		} else {
			mylog(LOG_INFO, "[%s] Logged out: %s", LINK(server)->name, irc_line_to_string(line));
		}
		ret = OK_FORGET;
	} else if (irc_line_elem_equals(line, 0, "902")) {
		mylog(LOG_INFO, "[%s] Account unavailable: %s",
			LINK(server)->name, irc_line_to_string(line));
		ret = OK_FORGET;
	} else if (irc_line_elem_equals(line, 0, "903")) {
		mylog(LOG_INFO, "[%s] SASL authentication successful", LINK(server)->name);
		WRITE_LINE1(CONN(server), NULL, "CAP", "END");
		ret = OK_FORGET;
	} else if (irc_line_elem_equals(line, 0, "904")) {
		mylog(LOG_ERROR, "[%s] SASL authentication failed", LINK(server)->name);
		ret = ERR_AUTH;
	} else if (irc_line_elem_equals(line, 0, "905")) {
		mylog(LOG_ERROR, "[%s] SASL message too long", LINK(server)->name);
		ret = ERR_AUTH;
	} else if (irc_line_elem_equals(line, 0, "906")) {
		mylog(LOG_ERROR, "[%s] SASL authentication aborted by client",
			LINK(server)->name);
		ret = ERR_AUTH;
	} else if (irc_line_elem_equals(line, 0, "907")) {
		mylog(LOG_ERROR, "[%s] SASL authentication has already been completed",
			LINK(server)->name);
		ret = OK_FORGET;
	} else if (irc_line_elem_equals(line, 0, "908")) {
		mylog(LOG_ERROR, "[%s] Server only accepts following authentication mechanisms: %s",
			LINK(server)->name, irc_line_elem(line, 2));
		ret = ERR_AUTH;
	} else if (irc_line_elem_equals(line, 0, "433")) {
		if (LINK(server)->s_state != IRCS_CONNECTED) {
			size_t nicklen = strlen(server->nick);
			char *newnick = bip_malloc(nicklen + 2);

			strcpy(newnick, server->nick);
			if (strlen(server->nick) < 9) {
				strcat(newnick, "`");
			} else {
				if (newnick[7] != '`') {
					if (newnick[8] != '`') {
						newnick[8] = '`';
					} else {
						newnick[7] = '`';
					}
				} else {
					newnick[8] = rand() *
						('z' - 'a') / RAND_MAX + 'a';
				}
				newnick[9] = 0;
			}
			ls_set_nick(server, newnick);

			WRITE_LINE1(CONN(server), NULL, "NICK", server->nick);
			ret = OK_FORGET;
		}
	} else if (LINK(server)->s_state == IRCS_RECONNECTING) {
		ret = OK_FORGET;
		if (irc_line_elem_equals(line, 0, "376")) /* end of motd */
			irc_server_connected(server);
		else if (irc_line_elem_equals(line, 0, "422")) /* no motd */
				irc_server_connected(server);

	} else if (LINK(server)->s_state == IRCS_CONNECTING) {
		ret = OK_FORGET;
			if (irc_line_elem_equals(line, 0, "005")) {
			int i;
			for (i = irc_line_count(line) - 1; i > 0; i--) {
				if (LINK(server)->ignore_server_capab &&
						irc_line_elem_equals(line, i, "CAPAB"))
					irc_line_drop(line, i);
				else if (!strncmp(irc_line_elem(line, i), "CHANMODES=", (size_t)10))
					server_set_chanmodes(server, irc_line_elem(line, i) + 10);
				else if (!strncmp(irc_line_elem(line, i), "PREFIX=(", (size_t)8))
					server_set_prefix(server, irc_line_elem(line, i) + 7);
			}
		}
		if (irc_line_elem_equals(line, 0, "NOTICE")) {
		} else if (irc_line_elem_equals(line, 0, "376")) {
							/* end of motd */
			irc_server_connected(server);
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		} else if (irc_line_elem_equals(line, 0, "422")) { /* no motd */
			irc_server_connected(server);
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		} else {
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		}
	} else if (irc_line_elem_equals(line, 0, "001")) {
		ret = irc_001(server, line);
		if (LINK(server)->s_state == IRCS_CONNECTING) {
			if (!list_is_empty(&LINK(server)->init_strings))
				return ERR_PROTOCOL;
			/* update the irc mask */
			list_add_last(&LINK(server)->init_strings,
					irc_line_dup(line));
		}
	} else if (irc_line_elem_equals(line, 0, "JOIN")) {
		ret = irc_join(server, line);
	} else if (irc_line_elem_equals(line, 0, "332")) {
		ret = irc_332(server, line);
	} else if (irc_line_elem_equals(line, 0, "333")) {
		ret = irc_333(server, line);
	} else if (irc_line_elem_equals(line, 0, "352")) {
		ret = irc_352(server, line);
	} else if (irc_line_elem_equals(line, 0, "315")) {
		ret = irc_315(server, line);
	} else if (irc_line_elem_equals(line, 0, "353")) {
		ret = irc_353(server, line);
	} else if (irc_line_elem_equals(line, 0, "366")) {
		ret = irc_366(server, line);
	} else if (irc_line_elem_equals(line, 0, "367")) {
		ret = irc_367(server, line);
	} else if (irc_line_elem_equals(line, 0, "368")) {
		ret = irc_368(server, line);
	} else if (irc_line_elem_equals(line, 0, "PART")) {
		ret = irc_part(server, line);
	} else if (irc_line_elem_equals(line, 0, "MODE")) {
		ret = irc_mode(server, line);
	} else if (irc_line_elem_equals(line, 0, "TOPIC")) {
		ret = irc_topic(server, line);
	} else if (irc_line_elem_equals(line, 0, "KICK")) {
		ret = irc_kick(server, line);
	} else if (irc_line_elem_equals(line, 0, "PRIVMSG")) {
		ret = irc_privmsg(server, line);
	} else if (irc_line_elem_equals(line, 0, "NOTICE")) {
		ret = irc_notice(server, line);
	} else if (irc_line_elem_equals(line, 0, "QUIT")) {
		ret = irc_quit(server, line);
	} else if (irc_line_elem_equals(line, 0, "NICK")) {
		ret = irc_nick(server, line);
	}

	if (ret == OK_COPY) {
		int i;
		for (i = 0; i < LINK(server)->l_clientc; i++) {
			if (TYPE(LINK(server)->l_clientv[i]) ==
					IRC_TYPE_CLIENT) {
				char *s = irc_line_to_string(line);
				write_line(CONN(LINK(server)->l_clientv[i]), s);
				free(s);
			}
		}
	}
	if (ret == OK_COPY_WHO && LINK(server)->who_client) {
		char *s;

		s = irc_line_to_string(line);
		write_line(CONN(LINK(server)->who_client), s);
		free(s);
	}
	if (LINK(server)->who_client &&
			LINK(server)->who_client->who_count == 0) {
		mylog(LOG_DEBUG, "OK_COPY_WHO: who_count for %p is nul",
			LINK(server)->who_client);
		rotate_who_client(LINK(server));
	}
	return ret;
}

/* send join and related stuff to client */
static void irc_send_join(struct link_client *ic, struct channel *chan)
{
	struct bipuser *user;
	char *ircmask;

	user = LINK(ic)->user;
	assert(user);

	/* user ircmask here for rbot */
	ircmask = bip_malloc(strlen(LINK(ic)->l_server->nick) +
			strlen(BIP_FAKEMASK) + 1);
	strcpy(ircmask, LINK(ic)->l_server->nick);
	strcat(ircmask, BIP_FAKEMASK);
	WRITE_LINE1(CONN(ic), ircmask, "JOIN", chan->name);
	free(ircmask);

	if (chan->topic)
		WRITE_LINE3(CONN(ic), P_SERV, "332", LINK(ic)->l_server->nick,
				chan->name, chan->topic);
	if (chan->creator && chan->create_ts)
		WRITE_LINE4(CONN(ic), P_SERV, "333", LINK(ic)->l_server->nick,
				chan->name, chan->creator, chan->create_ts);

	list_t *name_list = channel_name_list(LINK(ic)->l_server, chan);
	char *s;
	while ((s = list_remove_first(name_list))) {
		char tmptype[2];
		tmptype[0] = chan->type;
		tmptype[1] = 0;
		WRITE_LINE4(CONN(ic), P_SERV, "353", LINK(ic)->l_server->nick,
				tmptype, chan->name, s);
		free(s);
	}
	list_free(name_list);

	WRITE_LINE3(CONN(ic), P_SERV, "366", LINK(ic)->l_server->nick,
			chan->name, "End of /NAMES list.");
}

static void write_init_string(connection_t *c, struct line *line, char *nick)
{
	char *l;

	l = irc_line_to_string_to(line, nick);
	write_line(c, l);
	free(l);
}

static void bind_to_link(struct link *l, struct link_client *ic)
{
	int i = l->l_clientc;

	LINK(ic) = l;
	l->l_clientc++;
	l->l_clientv = bip_realloc(l->l_clientv, l->l_clientc *
			sizeof(struct link_client *));
	l->l_clientv[i] = ic;
}

void unbind_from_link(struct link_client *ic)
{
	struct link *l = LINK(ic);
	int i;

	for (i = 0; i < l->l_clientc; i++)
		if (l->l_clientv[i] == ic)
			break;

	assert(i != l->l_clientc);

	if (l->who_client == ic) {
		mylog(LOG_DEBUG, "unbind_from_link:  %p: %d", l->who_client,
				ic->who_count);
		l->who_client = NULL;
	}

	for (i = i + 1; i < l->l_clientc; i++)
		l->l_clientv[i - 1] = l->l_clientv[i];

	l->l_clientc--;
	l->l_clientv = bip_realloc(l->l_clientv, l->l_clientc *
			sizeof(struct link_client *));
	if (l->l_clientc == 0) { /* bip_realloc was equiv to free() */
		l->l_clientv = NULL;
		return;
	}
}

int irc_cli_bip(bip_t *bip, struct link_client *ic, struct line *line)
{
	return adm_bip(bip, ic, line, 0);
}

#define PASS_SEP ':'

static char *get_str_elem(char *str, int num)
{
	char *ret;
	char *c;
	char *cur = str;
	int index = 0;

	while ((c = strchr(cur, PASS_SEP))) {
		if (index < num) {
			index++;
			cur = c + 1;
			continue;
		}
		if (c - cur < 1)
			return NULL;
		ret = bip_malloc(c - cur + 1);
		memcpy(ret, cur, c - cur);
		ret[c - cur] = 0;
		return ret;
	}
	if (index == num) {
		c = str + strlen(str);
		if (c - cur < 1)
			return NULL;
		ret = bip_malloc(c - cur + 1);
		memcpy(ret, cur, c - cur);
		ret[c - cur] = 0;
		return ret;
	}
	return NULL;
}

static void irc_cli_make_join(struct link_client *ic)
{
	if (LINK(ic)->l_server) {
		/* join channels, step one, those in conf, in order */
		list_iterator_t li;
		for (list_it_init(&LINK(ic)->chan_infos_order, &li);
				list_it_item(&li); list_it_next(&li)) {
			struct chan_info *ci = (struct chan_info *)
				list_it_item(&li);
			struct channel *chan;
			if ((chan = hash_get(&LINK(ic)->l_server->channels,
							ci->name)))
				irc_send_join(ic, chan);
		}

		/* step two, those not in conf */
		hash_iterator_t hi;
		for (hash_it_init(&LINK(ic)->l_server->channels, &hi);
				hash_it_item(&hi); hash_it_next(&hi)) {
			struct channel *chan = (struct channel *)
				hash_it_item(&hi);
			if (!hash_get(&LINK(ic)->chan_infos, chan->name))
				irc_send_join(ic, chan);
		}
	}
}

void irc_cli_backlog(struct link_client *ic, int hours)
{
	struct bipuser *user;

	user = LINK(ic)->user;
	assert(user);
	assert(LINK(ic)->l_server);

	if (!user->backlog) {
		mylog(LOG_DEBUG, "Backlog disabled for %s, not backlogging",
				user->name);
		return;
	}

	if (hours != 0) {
		/* have some limit */
		if (hours > 24 * 366)
			hours = 24 * 366;
	}

	list_t *backlogl;
	char *bl;
	list_t *bllines;

	backlogl = log_backlogs(LINK(ic)->log);
	while ((bl = list_remove_first(backlogl))) {
		bllines = backlog_lines(LINK(ic)->log, bl,
				LINK(ic)->l_server->nick, hours);
		if (bllines) {
			if (!list_is_empty(bllines)) {
				mylog(LOG_INFO, "[%s] backlogging: %s",
						LINK(ic)->name, bl);
				write_lines(CONN(ic), bllines);
			}
			list_free(bllines);
		}
		free(bl);
	}
	list_free(backlogl);
}

static int irc_cli_startup(bip_t *bip, struct link_client *ic,
		struct line *line)
{
	char *init_nick;
	char *user, *pass, *connname;
	(void)line;

	assert(ic->init_pass);

	user = get_str_elem(ic->init_pass, 0);
	if (!user)
		return ERR_AUTH;
	pass = get_str_elem(ic->init_pass, 1);
	if (!pass) {
		free(user);
		return ERR_AUTH;
	}
	connname = get_str_elem(ic->init_pass, 2);
	if (!connname) {
		free(pass);
		free(user);
		return ERR_AUTH;
	}

	list_iterator_t it;
	for (list_it_init(&bip->link_list, &it); list_it_item(&it);
			list_it_next(&it)) {
		struct link *l = list_it_item(&it);
		if (strcmp(user, l->user->name) == 0 &&
				strcmp(connname, l->name) == 0) {
			if (chash_cmp(pass, l->user->password,
						l->user->seed) == 0) {
				bind_to_link(l, ic);
				break;
			}
		}
	}

	if (!LINK(ic))
		mylog(LOG_ERROR, "[%s] Invalid credentials (user: %s)",
				 connname, user);
	free(user);
	free(connname);
	free(pass);

	free(ic->init_pass);
	ic->init_pass = NULL;
	init_nick = ic->init_nick;
	ic->init_nick = NULL;

	if (!LINK(ic)) {
		free(init_nick);
		return ERR_AUTH;
	}

#ifdef HAVE_LIBSSL
	if (LINK(ic)->s_state != IRCS_CONNECTED) {
		/* Check if we have an untrusted certificate from the server */
		if (ssl_check_trust(ic)) {
			free(init_nick);
			return OK_FORGET;
		}
	}
#endif

	if (LINK(ic)->s_state == IRCS_NONE) {
		/* drop it if corresponding server hasn't connected at all. */
		write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
				":ERROR Proxy not yet connected, try again "
				"later\r\n");
		unbind_from_link(ic);
		free(init_nick);
		return OK_CLOSE;
	}

	list_remove(&bip->connecting_client_list, ic);
	TYPE(ic) = IRC_TYPE_CLIENT;

	for (list_it_init(&LINK(ic)->init_strings, &it);
			list_it_item(&it); list_it_next(&it))
		write_init_string(CONN(ic), list_it_item(&it), init_nick);

	/* we change nick on server */
	if (LINK(ic)->l_server) {
		struct link_server *server = LINK(ic)->l_server;
		WRITE_LINE1(CONN(ic), init_nick, "NICK", server->nick);

		if (!LINK(ic)->ignore_first_nick)
			WRITE_LINE1(CONN(server), NULL, "NICK", init_nick);
		else if (LINK(ic)->away_nick &&
				strcmp(LINK(ic)->away_nick, server->nick) == 0)
			WRITE_LINE1(CONN(server), NULL, "NICK",
					LINK(server)->connect_nick);

		/* change away status */
		if (server && LINK(ic)->no_client_away_msg)
			WRITE_LINE0(CONN(server), NULL, "AWAY");
	}

	if (!LINK(ic)->l_server) {
		free(init_nick);
		return OK_FORGET;
	}

	irc_cli_make_join(ic);
	irc_cli_backlog(ic, 0);

	log_client_connected(LINK(ic)->log);
	free(init_nick);

	return OK_FORGET;
}

static int irc_cli_nick(bip_t *bip, struct link_client *ic, struct line *line)
{
	if (irc_line_count(line) != 2)
		return ERR_PROTOCOL;

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return OK_COPY;

	ic->state |= IRCC_NICK;
	if (ic->init_nick)
		free(ic->init_nick);
	ic->init_nick = bip_strdup(irc_line_elem(line, 1));

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return irc_cli_startup(bip, ic, line);

	if ((ic->state & IRCC_PASS) != IRCC_PASS)
		WRITE_LINE2(CONN(ic), P_SERV, "NOTICE", ic->init_nick,
				"You should type /QUOTE PASS your_username:"
				"your_password:your_connection_name");

	return OK_FORGET;
}

static int irc_cli_user(bip_t *bip, struct link_client *ic, struct line *line)
{
	if (irc_line_count(line) != 5)
		return ERR_PROTOCOL;

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return ERR_PROTOCOL;

	ic->state |= IRCC_USER;
	if ((ic->state & IRCC_READY) == IRCC_READY)
		return irc_cli_startup(bip, ic, line);
	return OK_FORGET;
}

static int irc_cli_pass(bip_t *bip, struct link_client *ic, struct line *line)
{
	if (irc_line_count(line) != 2)
		return ERR_PROTOCOL;

	if ((ic->state & IRCC_READY) == IRCC_READY)
		return ERR_PROTOCOL;

	ic->state |= IRCC_PASS;
	if (ic->init_pass)
		free(ic->init_pass);
	ic->init_pass = bip_strdup(irc_line_elem(line, 1));
	if ((ic->state & IRCC_READY) == IRCC_READY)
		return irc_cli_startup(bip, ic, line);
	return OK_FORGET;
}

static int irc_cli_quit(struct link_client *ic, struct line *line)
{
	(void)ic;
	(void)line;
	return OK_CLOSE;
}

static int irc_cli_privmsg(bip_t *bip, struct link_client *ic,
		struct line *line)
{
	if (!irc_line_includes(line, 2))
		return OK_FORGET;

	if (irc_line_elem_equals(line, 1, "-bip"))
		return adm_bip(bip, ic, line, 1);
	else
		log_cli_privmsg(LINK(ic)->log, LINK(ic)->l_server->nick,
			irc_line_elem(line, 1), irc_line_elem(line, 2));

	if (LINK(ic)->user->blreset_on_talk) {
		if (LINK(ic)->user->blreset_connection)
			log_reset_all(LINK(ic)->log);
		else
			log_reset_store(LINK(ic)->log, irc_line_elem(line, 1));
	}
	return OK_COPY_CLI;
}

static int irc_cli_notice(struct link_client *ic, struct line *line)
{
	if (!irc_line_includes(line, 2))
		return OK_FORGET;
	log_cli_notice(LINK(ic)->log, LINK(ic)->l_server->nick,
				irc_line_elem(line, 1), irc_line_elem(line, 2));
	if (LINK(ic)->user->blreset_on_talk) {
		if (LINK(ic)->user->blreset_connection)
			log_reset_all(LINK(ic)->log);
		else
			log_reset_store(LINK(ic)->log, irc_line_elem(line, 1));
	}
	return OK_COPY_CLI;
}

static int irc_cli_who(struct link_client *ic, struct line *line)
{
	struct link *l = LINK(ic);

	++ic->who_count;
	if (ic->who_count == 1)
		ic->whoc_tstamp = time(NULL);
	mylog(LOG_DEBUG, "cli_who: Incrementing who count for %p: %d",
				ic, ic->who_count);

	if (l->who_client && l->who_client != ic) {
		list_add_first(&ic->who_queue, irc_line_to_string(line));
		return OK_FORGET;
	}

	if (!l->who_client)
		l->who_client = ic;

	return OK_COPY;
}

static int irc_cli_mode(struct link_client *ic, struct line *line)
{
	struct link *l = LINK(ic);

	if (irc_line_count(line) != 3)
		return OK_COPY;

	/* This is a wild guess and that sucks. */
	if (!irc_line_elem_equals(line, 0, "MODE") ||
			strchr(irc_line_elem(line, 2), 'b') == NULL)
		return OK_COPY;

	++ic->who_count;
	if (ic->who_count == 1)
		ic->whoc_tstamp = time(NULL);
	mylog(LOG_DEBUG, "cli_mode: Incrementing who count for %p: %d",
				l->who_client, ic->who_count);

	if (l->who_client && l->who_client != ic) {
		list_add_first(&ic->who_queue, irc_line_to_string(line));
		return OK_FORGET;
	}

	if (!l->who_client)
		l->who_client = ic;

	return OK_COPY;
}


static void irc_notify_disconnection(struct link_server *is)
{
	int i;
	LINK(is)->cli_nick = bip_strdup(is->nick);

	for (i = 0; i < LINK(is)->l_clientc; i++) {
		struct link_client *ic = LINK(is)->l_clientv[i];
		hash_iterator_t hi;
		for (hash_it_init(&is->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
			struct channel *c = (struct channel *)hash_it_item(&hi);
			WRITE_LINE3(CONN(ic), P_IRCMASK, "KICK",
					c->name, is->nick,
					"Server disconnected, reconnecting");
		}
		bip_notify(ic, "Server disconnected, reconnecting");
	}
}

void irc_add_channel_info(struct link_server *ircs, const char *chan,
		const char *key)
{
	struct chan_info *ci;
	if (!ischannel(*chan))
		return;

	ci = hash_get(&LINK(ircs)->chan_infos, chan);
	if (!ci) {
		struct chan_info *ci;
		ci = chan_info_new();
		ci->name = bip_strdup(chan);
		ci->key = key ? bip_strdup(key) : NULL;
		ci->backlog = 1;
		hash_insert(&LINK(ircs)->chan_infos, chan, ci);
		list_add_last(&LINK(ircs)->chan_infos_order, ci);
	} else {
		if (ci->key) {
			free(ci->key);
			ci->key = NULL;
		}
		ci->key = key ? bip_strdup(key) : NULL;
	}
}

static int irc_cli_join(struct link_client *irc, struct line *line)
{
	if (irc_line_count(line) != 2 && irc_line_count(line) != 3)
		return ERR_PROTOCOL;

	const char *s, *e, *ks, *ke = NULL;
	s = irc_line_elem(line, 1);
	if (irc_line_count(line) == 3)
		ks = irc_line_elem(line, 2);
	else
		ks = NULL;

	while ((e = strchr(s, ','))) {
		size_t len = e - s;
		char *p = bip_malloc(len + 1);
		size_t klen;
		char *kp = NULL;

		memcpy(p, s, len);
		p[len] = 0;
		if (ks) {
			if (strlen(ks)) {
				ke = strchr(ks, ',');
				if (!ke)
					ke = ks + strlen(ks);
				klen = ke - ks;
				kp = bip_malloc(klen + 1);
				memcpy(kp, ks, klen);
				kp[klen] = 0;
				if (*ke == 0)
					ks = NULL;
			} else {
				kp = NULL;
				ks = NULL;
			}
		}

		irc_add_channel_info(LINK(irc)->l_server, p, kp);
		free(p);
		if (kp) {
			free(kp);
			if (ks)
				ks = ke + 1;
		}
		s = e + 1;
	}

	irc_add_channel_info(LINK(irc)->l_server, s, ks);
	return OK_COPY;
}

static int irc_cli_part(struct link_client *irc, struct line *line)
{
	struct chan_info *ci;
	char *cname;

	if (irc_line_count(line) != 2 && irc_line_count(line) != 3)
		return ERR_PROTOCOL;

	cname = (char *)irc_line_elem(line, 1);

	if ((ci = hash_remove_if_exists(&LINK(irc)->chan_infos,
					cname)) != NULL) {
		list_remove(&LINK(irc)->chan_infos_order, ci);
		free(ci->name);
		if (ci->key)
			free(ci->key);
		free(ci);
	}
	return OK_COPY;
}

#ifdef HAVE_LIBSSL
static int irc_dispatch_trust_client(struct link_client *ic, struct line *line)
{
	int r = OK_COPY;
	if (!irc_line_includes(line, 1))
		return ERR_PROTOCOL;

	if (strcasecmp(irc_line_elem(line, 0), "BIP") == 0 &&
	    strcasecmp(irc_line_elem(line, 1), "TRUST") == 0)
		r = adm_trust(ic, line);

	return r;
}
#endif

static int irc_dispatch_client(bip_t *bip, struct link_client *ic,
		struct line *line)
{
	int r = OK_COPY;
	if (irc_line_count(line) == 0)
		return ERR_PROTOCOL;

	if (irc_line_elem_equals(line, 0, "PING")) {
		if (!irc_line_includes(line, 1))
			return ERR_PROTOCOL;
		WRITE_LINE1(CONN(ic), link_name((struct link_any *)ic), "PONG",
				irc_line_elem(line, 1));
		r = OK_FORGET;
	} else if (LINK(ic)->s_state != IRCS_CONNECTED) {
		write_line_fast(CONN(ic), ":irc.bip.net NOTICE pouet "
				":ERROR Proxy not connected, please wait "
				"before sending commands\r\n");
		r = OK_FORGET;
	} else if (strcasecmp(irc_line_elem(line, 0), "BIP") == 0) {
		r = irc_cli_bip(bip, ic, line);
	} else if (irc_line_elem_equals(line, 0, "JOIN")) {
		r = irc_cli_join(ic, line);
	} else if (irc_line_elem_equals(line, 0, "PART")) {
		r = irc_cli_part(ic, line);
	} else if (irc_line_elem_equals(line, 0, "NICK")) {
		r = irc_cli_nick(bip, ic, line);
	} else if (irc_line_elem_equals(line, 0, "QUIT")) {
		r = irc_cli_quit(ic, line);
	} else if (irc_line_elem_equals(line, 0, "PRIVMSG")) {
		r = irc_cli_privmsg(bip, ic, line);
	} else if (irc_line_elem_equals(line, 0, "NOTICE")) {
		r = irc_cli_notice(ic, line);
	} else if (irc_line_elem_equals(line, 0, "WHO")) {
		r = irc_cli_who(ic, line);
	} else if (irc_line_elem_equals(line, 0, "MODE")) {
		r = irc_cli_mode(ic, line);
	}

	if (r == OK_COPY || r == OK_COPY_CLI) {
		char *str = irc_line_to_string(line);
		if (LINK(ic)->s_state == IRCS_CONNECTED &&
				LINK(ic)->l_server->nick)
			write_line(CONN(LINK(ic)->l_server), str);
		else if (LINK(ic)->l_server->nick)
			WRITE_LINE2(CONN(ic), P_IRCMASK,
					(LINK(ic)->user->bip_use_notice ?
						"NOTICE" : "PRIVMSG"),
					LINK(ic)->l_server->nick,
					":Not connected please try again "
					"later...\r\n");

		free(str);
		if (r == OK_COPY_CLI) {
			int i;
			struct link_server *s = LINK(ic)->l_server;

			for (i = 0; i < LINK(s)->l_clientc; i++)
				irc_copy_cli(ic, LINK(s)->l_clientv[i], line);
		}
	}
	return r;
}

static void irc_copy_cli(struct link_client *src, struct link_client *dest,
		struct line *line)
{
	char *str;

	if (src == dest)
		return;

	if (!irc_line_includes(line, 1) ||
			!irc_line_elem_equals(line, 0, "PRIVMSG")) {
		str = irc_line_to_string(line);
		write_line(CONN(dest), str);
		free(str);
		return;
	}

	if (ischannel(*irc_line_elem(line, 1)) || LINK(src) != LINK(dest)) {
		assert(!line->origin);
		line->origin = LINK(src)->l_server->nick;
		str = irc_line_to_string(line);
		line->origin = NULL;
		write_line(CONN(dest), str);
		free(str);
		return;
	}

	/* LINK(src) == LINK(dest) */
	size_t len = strlen(irc_line_elem(line, 2)) + 5;
	char *tmp;

	if (len == 0)
		return;

	tmp = bip_malloc(len);

	snprintf(tmp, len, " -> %s", irc_line_elem(line, 2));
	tmp[len - 1] = 0;

	struct line *retline = irc_line_new();

	retline->origin = bip_strdup(irc_line_elem(line, 1));
	irc_line_append(retline, irc_line_elem(line, 0));
	irc_line_append(retline, LINK(src)->l_server->nick);
	irc_line_append(retline, tmp);
	free(tmp);
	str = irc_line_to_string(retline);
	irc_line_free(retline);
#if 0
	/* tricky: */
	irc_line_elem(line, 1) = LINK(src)->l_server->nick;

	oldelem = irc_line_elem(line, 2);
	irc_line_elem(line, 2) = tmp;
	str = irc_line_to_string(line);
	/* end of trick: */
	irc_line_elem(line, 1) = line->origin;
	irc_line_elem(line, 2) = oldelem;
	line->origin = NULL;
#endif
	write_line(CONN(dest), str);
	free(str);
	return;
}

static int irc_dispatch_logging_client(bip_t *bip, struct link_client *ic,
		struct line *line)
{
	if (irc_line_count(line) == 0)
		return ERR_PROTOCOL;

	if (irc_line_elem_equals(line, 0, "NICK")) {
		return irc_cli_nick(bip, ic, line);
	} else if (irc_line_elem_equals(line, 0, "USER")) {
		return irc_cli_user(bip, ic, line);
	} else if (irc_line_elem_equals(line, 0, "PASS")) {
		return irc_cli_pass(bip, ic, line);
	}
	return OK_FORGET;
}

int irc_dispatch(bip_t *bip, struct link_any *l, struct line *line)
{
	switch (TYPE(l)) {
	case IRC_TYPE_SERVER:
		return irc_dispatch_server(bip, (struct link_server*)l, line);
		break;
	case IRC_TYPE_CLIENT:
		return irc_dispatch_client(bip, (struct link_client*)l, line);
		break;
	case IRC_TYPE_LOGGING_CLIENT:
		return irc_dispatch_logging_client(bip, (struct link_client*)l,
				line);
		break;
#ifdef HAVE_LIBSSL
	case IRC_TYPE_TRUST_CLIENT:
		return irc_dispatch_trust_client((struct link_client*)l, line);
		break;
#endif
	default:
		fatal("irc_dispatch: unknown IRC_TYPE_SERVER");
	}
	return ERR_PROTOCOL; /* never reached */
}

static int origin_is_me(struct line *l, struct link_server *server)
{
	char *nick;

	if (!l->origin)
		return 0;
	nick = nick_from_ircmask(l->origin);
	if (strcasecmp(nick, server->nick) == 0) {
		free(nick);
		return 1;
	}
	free(nick);
	return 0;
}

static int irc_join(struct link_server *server, struct line *line)
{
	char *s_nick;
	const char *s_chan;
	struct channel *channel;

	if (irc_line_count(line) != 2 && irc_line_count(line) != 3)
		return ERR_PROTOCOL;

	s_chan = irc_line_elem(line, 1);
	log_join(LINK(server)->log, line->origin, s_chan);

	channel = hash_get(&server->channels, s_chan);
	if (origin_is_me(line, server)) {
		if (!channel) {
			channel = channel_new(s_chan);
			hash_insert(&server->channels, s_chan, channel);
		}
		return OK_COPY;
	}
	/* if we're not on channel and !origin_is_me, we should not get any
	 * JOIN */
	if (!channel)
		return ERR_PROTOCOL;
	if (!line->origin)
		return ERR_PROTOCOL;

	s_nick = nick_from_ircmask(line->origin);
	hash_insert(&channel->ovmasks, s_nick, 0);
	free(s_nick);
	return OK_COPY;
}

static int irc_332(struct link_server *server, struct line *line)
{
	struct channel *channel;
	if (irc_line_count(line) != 4)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, irc_line_elem(line, 2));
	/* we can get topic reply for chans we're not on */
	if (!channel)
		return OK_COPY;

	if (channel->topic)
		free(channel->topic);
	channel->topic = bip_strdup(irc_line_elem(line, 3));

	log_init_topic(LINK(server)->log, channel->name, channel->topic);
	return OK_COPY;
}

static int irc_333(struct link_server *server, struct line *line)
{
	struct channel *channel;
	if (!irc_line_includes(line, 2))
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, irc_line_elem(line, 2));
	/* we can get topic info reply for chans we're not on */
	if (!channel)
		return OK_COPY;
	if (channel->creator)
		free(channel->creator);
	if (channel->create_ts)
		free(channel->create_ts);
	if (irc_line_count(line) == 5) {
		channel->creator = bip_strdup(irc_line_elem(line, 3));
		channel->create_ts = bip_strdup(irc_line_elem(line, 4));
	} else {
		channel->creator = bip_strdup("");
		channel->create_ts = bip_strdup("0");
	}
	log_init_topic_time(LINK(server)->log, channel->name, channel->creator,
			channel->create_ts);
	return OK_COPY;
}

static int irc_353(struct link_server *server, struct line *line)
{
	struct channel *channel;
	const char *names, *eon;
	size_t len;
	char *nick;

	if (irc_line_count(line) != 5)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, irc_line_elem(line, 3));
	/* we can get names reply for chans we're not on */
	if (!channel)
		return OK_COPY;

	if (!channel->running_names) {
		channel->running_names = 1;
		hash_clean(&channel->ovmasks);
	}

	/* TODO check that type is one of "=" / "*" / "@" */
	channel->type = irc_line_elem(line, 2)[0];

	names = irc_line_elem(line, 4);

	int index;
	while (*names) {
		long int ovmask = 0;
		/* some ircds (e.g. unreal) may display several flags for the
                   same nick */
		while ((index = bip_get_index(server->prefixes, *names))) {
			ovmask |= 1 << index;
			names++;
		}
		eon = names;
		while (*eon && *eon != ' ')
			eon++;

		len = eon - names;
		nick = bip_malloc(len + 1);
		memcpy(nick, names, len);
		nick[len] = 0;

		/* we just ignore names for nicks that are crazy long */
		if (len + 2 < NAMESIZE)
			hash_insert(&channel->ovmasks, nick, (void *)ovmask);
		free(nick);

		while (*eon && *eon == ' ')
			eon++;
		names = eon;
	}
	return OK_COPY;
}

static int irc_366(struct link_server *server, struct line *line)
{
	struct channel *channel;

	if (irc_line_count(line) != 4)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, irc_line_elem(line, 2));
	if (channel && channel->running_names)
		channel->running_names = 0;
	return OK_COPY;
}

static int irc_367(struct link_server *server, struct line *l)
{
	(void)server;
	(void)l;
	return OK_COPY_WHO;
}

/* same as irc_315 */
static int irc_368(struct link_server *server, struct line *l)
{
	(void)l;
	struct link *link = LINK(server);
	if (link->who_client) {
		if (link->who_client->who_count == 0) {
			mylog(LOG_DEBUG, "Spurious irc_368");
			return OK_COPY_WHO;
		}
		link->who_client->whoc_tstamp = time(NULL);

		if (link->who_client->who_count > 0) {
			--link->who_client->who_count;
			mylog(LOG_DEBUG,
				"RPL_ENDOFBANLIST: "
				"Decrementing who count for %p: %d",
				link->who_client, link->who_client->who_count);
		}
	}

	return OK_COPY_WHO;
}

static void channel_free(struct channel *c)
{
	if (c->name)
		free(c->name);
	if (c->mode)
		free(c->mode);
	if (c->key)
		free(c->key);
	if (c->topic)
		free(c->topic);
	if (c->creator)
		free(c->creator);
	if (c->create_ts)
		free(c->create_ts);

	hash_clean(&c->ovmasks);
	free(c);
}

static int irc_part(struct link_server *server, struct line *line)
{
	char *s_nick;
	const char *s_chan;
	struct channel *channel;

	if (irc_line_count(line) != 2 && irc_line_count(line) != 3)
		return ERR_PROTOCOL;

	s_chan = irc_line_elem(line, 1);

	channel = hash_get(&server->channels, s_chan);
	/* we can't get part message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;

	if (origin_is_me(line, server)) {
		log_part(LINK(server)->log, line->origin, s_chan,
			irc_line_count(line) == 3 ? irc_line_elem(line, 2) :
				NULL);
		log_reset_store(LINK(server)->log, s_chan);
		log_drop(LINK(server)->log, s_chan);

		hash_remove(&server->channels, s_chan);
		channel_free(channel);
		return OK_COPY;
	}

	if (!line->origin)
		return ERR_PROTOCOL;
	s_nick = nick_from_ircmask(line->origin);
	if (!hash_includes(&channel->ovmasks, s_nick)) {
		free(s_nick);
		return ERR_PROTOCOL;
	}
	hash_remove(&channel->ovmasks, s_nick);
	free(s_nick);

	log_part(LINK(server)->log, line->origin, s_chan,
			irc_line_count(line) == 3 ?
				irc_line_elem(line, 2) : NULL);

	return OK_COPY;
}

static void mode_add_letter_uniq(struct link_server *s, char c)
{
	int i;
	for (i = 0; i < s->user_mode_len; i++) {
		if (s->user_mode[i] == c)
			return;
	}
	s->user_mode = bip_realloc(s->user_mode, s->user_mode_len + 1);
	s->user_mode[s->user_mode_len++] = c;
}

static void mode_remove_letter(struct link_server *s, char c)
{
	int i;
	for (i = 0; i < s->user_mode_len; i++) {
		if (s->user_mode[i] == c) {
			for (; i < s->user_mode_len - 1; i++)
				s->user_mode[i] = s->user_mode[i + 1];
			s->user_mode_len--;
			s->user_mode = bip_realloc(s->user_mode,
					s->user_mode_len);
			return;
		}
	}
}

static void irc_user_mode(struct link_server *server, struct line *line)
{
	const char *mode;
	int add = 1;

	for (mode = irc_line_elem(line, 2); *mode; mode++) {
		if (*mode == '-')
			add = 0;
		else if (*mode == '+')
			add = 1;
		else {
			if (add) {
				mode_add_letter_uniq(server, *mode);
			} else {
				mode_remove_letter(server, *mode);
			}
		}
	}
}

static int irc_mode(struct link_server *server, struct line *line)
{
	struct channel *channel;
	const char *mode;
	int add = 1;
	unsigned cur_arg = 0;
	array_t *mode_args = NULL;
	int ret;

	if (!irc_line_includes(line, 2))
		return ERR_PROTOCOL;

	/* nick mode change */
	if (irc_line_elem_equals(line, 1, server->nick)) {
		if (irc_line_includes(line, 3))
			mode_args = array_extract(&line->words, 3, -1);
		log_mode(LINK(server)->log, line->origin,
				irc_line_elem(line, 1), irc_line_elem(line, 2),
				mode_args);
		if (mode_args)
			array_free(mode_args);
		irc_user_mode(server, line);
		return OK_COPY;
	}

	if (!ischannel(irc_line_elem(line, 1)[0]))
		return ERR_PROTOCOL;

	/* channel mode change */
	channel = hash_get(&server->channels, irc_line_elem(line, 1));
	/* we can't get mode message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;

	mode_args = NULL;
	if (irc_line_includes(line, 3))
		mode_args = array_extract(&line->words, 3, -1);
	log_mode(LINK(server)->log, line->origin, irc_line_elem(line, 1),
			irc_line_elem(line, 2), mode_args);
	if (mode_args)
		array_free(mode_args);

	/*
	 * MODE -a+b.. #channel args
	 *         ^            ^
	 *       mode         cur_arg
	 */
	for (mode = irc_line_elem(line, 2); *mode; mode++) {
		if (*mode == '-')
			add = 0;
		else if (*mode == '+')
			add = 1;
		else {
			int i = 0;
			char *str = 0;

			// Check if mode is known: first user modes then
			// server modes
			if (!(str = strchr(server->usermodes, *mode))) {
				array_each(&server->chanmodes, i, str) {
					if ((str = strchr(str, *mode)))
						break;
				}
			}

			if (str) {
				// Usermodes, types A & B always take a parameter
				// Type C take a parameter only when set
				if (i <= 1 || (i == 2 && add)) {
					if (!irc_line_includes(line, cur_arg + 3)) {
						return ERR_PROTOCOL;
					} else {
						ret = irc_mode_channel(server, channel, line, mode,
								add, cur_arg);
						cur_arg++;
					}
				} else {
					ret = irc_mode_channel(server, channel, line, mode, add,
							cur_arg);
				}
			}
		}
		if (ret == ERR_PROTOCOL)
			return ret;
	}
	return OK_COPY;
}

static int irc_mode_channel(struct link_server *s, struct channel *channel,
				struct line *line, const char* mode, int add, int cur_arg)
{
	const char *nick;
	long int ovmask;
	int index;

	if (*mode == 'k') {
		if (add) {
			channel->key = bip_strdup(
				irc_line_elem(line, cur_arg + 3));
		} else {
			if (channel->key) {
				free(channel->key);
				channel->key = NULL;
			}
		}
	} else if ((index = bip_get_index(s->usermodes, *mode))) {
		nick = irc_line_elem(line, cur_arg + 3);

		if (!hash_includes(&channel->ovmasks, nick))
			return ERR_PROTOCOL;
		ovmask = (long int)hash_remove(&channel->ovmasks, nick);

		if (add)
			ovmask |= 1 << index;
		else
			ovmask &= ~(1 << index);
		hash_insert(&channel->ovmasks, nick, (void *)ovmask);
	}
	return OK_COPY;
}

static char *irc_timestamp(void)
{
	char *ts = bip_malloc((size_t)23);
	snprintf(ts, (size_t)22, "%ld", (long int)time(NULL));
	return ts;
}

static int irc_topic(struct link_server *server, struct line *line)
{
	struct channel *channel;
	const char *topic;

	if (irc_line_count(line) != 3)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, irc_line_elem(line, 1));
	/* we can't get topic message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;

	if (channel->topic)
		free(channel->topic);
	topic = irc_line_elem(line, 2);
	if (*topic == ':')
		topic++;
	channel->topic = bip_strdup(topic);

	/*
	 * :arion.oftc.net 333 bip`luser #bipqSDFQE3
	 * nohar!~nohar@borne28.noc.nerim.net 1107338095
	 */

	if (channel->creator)
		free(channel->creator);
	channel->creator = bip_strmaydup(line->origin);
	if (channel->create_ts)
		free(channel->create_ts);
	channel->create_ts = irc_timestamp();

	log_topic(LINK(server)->log, line->origin, irc_line_elem(line, 1),
			topic);
	return OK_COPY;
}

static int irc_kick(struct link_server *server, struct line *line)
{
	struct channel *channel;

	if (irc_line_count(line) != 3 && irc_line_count(line) != 4)
		return ERR_PROTOCOL;

	channel = hash_get(&server->channels, irc_line_elem(line, 1));
	/* we can't get kick message for chans we're not on */
	if (!channel)
		return ERR_PROTOCOL;

	if (!hash_includes(&channel->ovmasks, irc_line_elem(line, 2)))
		return ERR_PROTOCOL;

	if (strcasecmp(irc_line_elem(line, 2), server->nick) == 0) {
		/* we get kicked !! */
		log_kick(LINK(server)->log, line->origin, channel->name,
				irc_line_elem(line, 2),
				irc_line_count(line) == 4 ?
					irc_line_elem(line, 3) : NULL);
		log_reset_store(LINK(server)->log, channel->name);
		log_drop(LINK(server)->log, channel->name);

		if (LINK(server)->autojoin_on_kick) {
			if (!channel->key)
				WRITE_LINE1(CONN(server), NULL, "JOIN",
						channel->name);
			else
				WRITE_LINE2(CONN(server), NULL, "JOIN",
						channel->name, channel->key);
		}

		hash_remove(&server->channels, channel->name);
		channel_free(channel);
		return OK_COPY;
	}

	hash_remove(&channel->ovmasks, irc_line_elem(line, 2));
	log_kick(LINK(server)->log, line->origin, irc_line_elem(line, 1),
		irc_line_elem(line, 2),
		irc_line_count(line) == 4 ? irc_line_elem(line, 3) : NULL);


	return OK_COPY;
}

static void irc_privmsg_check_ctcp(struct link_server *server,
				   struct line *line)
{
	if (irc_line_count(line) != 3)
		return;

	if (!line->origin)
		return;

	char *nick;
	nick = nick_from_ircmask(line->origin);
	if (irc_line_elem_equals(line, 2, "\001VERSION\001")) {
		WRITE_LINE2(CONN(server), NULL, "NOTICE", nick,
				"\001VERSION bip-" PACKAGE_VERSION "\001");
	}
	free(nick);
}

static int irc_privmsg(struct link_server *server, struct line *line)
{
	if (!irc_line_includes(line, 2))
		return ERR_PROTOCOL;
	if (LINK(server)->s_state == IRCS_CONNECTED)
		log_privmsg(LINK(server)->log, line->origin,
				irc_line_elem(line, 1), irc_line_elem(line, 2));
	irc_privmsg_check_ctcp(server, line);
	return OK_COPY;
}

static int irc_notice(struct link_server *server, struct line *line)
{
	if (!irc_line_includes(line, 2))
		return ERR_PROTOCOL;
	if (LINK(server)->s_state == IRCS_CONNECTED)
		log_notice(LINK(server)->log, line->origin,
				irc_line_elem(line, 1), irc_line_elem(line, 2));
	return OK_COPY;
}

static int irc_quit(struct link_server *server, struct line *line)
{
	return irc_generic_quit(server, line);
}

static int irc_nick(struct link_server *server, struct line *line)
{
	struct channel *channel;
	hash_iterator_t hi;
	char *org_nick;
	const char *dst_nick;

	if (irc_line_count(line) != 2)
		return ERR_PROTOCOL;

	if (!line->origin)
		return ERR_PROTOCOL;

	org_nick = nick_from_ircmask(line->origin);
	dst_nick = irc_line_elem(line, 1);

	for (hash_it_init(&server->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		channel = hash_it_item(&hi);
		if (!hash_includes(&channel->ovmasks, org_nick))
			continue;
		hash_rename_key(&channel->ovmasks, org_nick, dst_nick);
		log_nick(LINK(server)->log, org_nick, channel->name, dst_nick);
	}

	if (origin_is_me(line, server)) {
		free(server->nick);
		server->nick = bip_strdup(dst_nick);
		if (LINK(server)->follow_nick &&
				(LINK(server)->away_nick == NULL ||
				strcmp(server->nick, LINK(server)->away_nick))
				!= 0) {
			free(LINK(server)->connect_nick);
			LINK(server)->connect_nick = bip_strdup(server->nick);
		}
	}

	free(org_nick);
	return OK_COPY;
}

static int irc_generic_quit(struct link_server *server, struct line *line)
{
	struct channel *channel;
	hash_iterator_t hi;
	char *s_nick;

	if (irc_line_count(line) != 2 && irc_line_count(line) != 1)
		return ERR_PROTOCOL;

	if (!line->origin)
		return ERR_PROTOCOL;
	s_nick = nick_from_ircmask(line->origin);
	for (hash_it_init(&server->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		channel = hash_it_item(&hi);
		if (!hash_includes(&channel->ovmasks, s_nick))
			continue;
		hash_remove(&channel->ovmasks, s_nick);
		log_quit(LINK(server)->log, line->origin, channel->name,
			irc_line_includes(line, 1) ?
				irc_line_elem(line, 1) : NULL);
	}
	free(s_nick);
	return OK_COPY;
}

static void ls_set_nick(struct link_server *ircs, char *nick)
{
	if (ircs->nick)
		free(ircs->nick);
	ircs->nick = nick;
#if 0
	if (ircs->ircmask) {
		char *eom = strchr(ircs->ircmask, '!');
		if (!eom) {
			free(ircs->ircmask);
			goto fake;
		}
		eom = bip_strdup(eom);
		free(ircs->ircmask);
		ircs->ircmask = bip_malloc(strlen(nick) + strlen(eom) + 1);
		strcpy(ircs->ircmask, nick);
		strcat(ircs->ircmask, eom);
		free(eom);
		return;
	}
fake:
	ircs->ircmask = bip_malloc(strlen(nick) + strlen(BIP_FAKEMASK) + 1);
	strcpy(ircs->ircmask, nick);
	strcat(ircs->ircmask, BIP_FAKEMASK);
#endif
}

static char *sasl_mechanism_to_text(int sasl_mechanism)
{
	switch (sasl_mechanism) {
	case SASL_AUTH_EXTERNAL:
		return "EXTERNAL";
	case SASL_AUTH_PLAIN:
		return "PLAIN";
	default:
		return "UNKOWN_MECHANISM";
	}
}

// Per RFC send packets of max 400 chars at a time
#define SASL_AUTH_CHUNK_SZ 400
static int irc_server_sasl_authenticate(struct link_server *ircs)
{
	char *sasl_username = LINK(ircs)->sasl_username;
	char *sasl_password = LINK(ircs)->sasl_password;

	if (LINK(ircs)->sasl_mechanism == SASL_AUTH_EXTERNAL) {
		WRITE_LINE1(CONN(ircs), NULL, "AUTHENTICATE", "+");
		return OK_FORGET;
	}

	// Should not happen, but we never know right ?
	if (!sasl_username || !sasl_password) {
		mylog(LOG_ERROR, "[%s] Missing SASL username or password.", LINK(ircs)->name);
		return ERR_AUTH;
	}

	/*
	 * Other than EXTERNAL we only support PLAIN.
	 */

	size_t chunk_chars = SASL_AUTH_CHUNK_SZ;
	char chunk[SASL_AUTH_CHUNK_SZ + 1];
	size_t u_len = strlen(sasl_username);
	size_t p_len = strlen(sasl_password);
	size_t raw_len = u_len*2 + p_len + 2;
	size_t enc_len;
	unsigned char *raw_str = bip_malloc(raw_len + 1);
	unsigned char *enc_str;

	memcpy(raw_str, sasl_username, u_len);
	raw_str[u_len] = '\0';
	memcpy(raw_str + u_len + 1, sasl_username, u_len);
	raw_str[u_len*2 + 1] = '\0';
	memcpy(raw_str + u_len*2 + 2, sasl_password, p_len);
	enc_str = base64_encode(raw_str, raw_len, &enc_len);
	mylog(LOG_DEBUG, "[%s] Base64 encoded SASL auth token (len %d): %s", LINK(ircs)->name, enc_len, enc_str);

	for (size_t i = 0; i < enc_len; i += chunk_chars) {
		size_t remaining = enc_len - i;
		if (remaining < chunk_chars) {
			memcpy(chunk, &enc_str[i], remaining);
			chunk[remaining]= '\0';
		} else {
			memcpy(chunk, &enc_str[i], chunk_chars);
			chunk[chunk_chars]= '\0';
		}
		mylog(LOG_DEBUG, "[%s] SASL AUTHENTICATE chunk %d, len %d: %s",
			LINK(ircs)->name, i/chunk_chars, strlen(chunk), chunk);
		WRITE_LINE1(CONN(ircs), NULL, "AUTHENTICATE", chunk);

		// Send a closing AUTHENTICATE line if last chunk size was exactly 400
		if (remaining == chunk_chars) {
			mylog(LOG_DEBUG, "[%s] Last SASL chunk was exactly 400, sending +",
				LINK(ircs)->name);
			WRITE_LINE1(CONN(ircs), NULL, "AUTHENTICATE", "+");
			break;
		}
	}
	free(enc_str);

	return OK_FORGET;
}

static void irc_server_startup(struct link_server *ircs)
{
	char *nick;
	char *username, *realname;

	/* lower the token number as freenode hates fast login */
        CONN(ircs)->token = 1;

	if (LINK(ircs)->s_password)
		WRITE_LINE1(CONN(ircs), NULL, "PASS", LINK(ircs)->s_password);

	username = LINK(ircs)->username;
	if (!username)
		username = LINK(ircs)->user->default_username;
	realname = LINK(ircs)->realname;
	if (!realname)
		realname = LINK(ircs)->user->default_realname;
	WRITE_LINE4(CONN(ircs), NULL, "USER", username, "0", "*", realname);

	nick = ircs->nick;
	if (LINK(ircs)->away_nick && LINK(ircs)->l_clientc == 0) {
		if (nick)
			free(nick);
		nick = bip_strdup(LINK(ircs)->away_nick);
	}
	if ((!LINK(ircs)->follow_nick && !LINK(ircs)->away_nick)
			|| nick == NULL) {
		if (nick)
			free(nick);
		if (!LINK(ircs)->connect_nick)
			LINK(ircs)->connect_nick =
				bip_strdup(LINK(ircs)->user->default_nick);
		nick = bip_strdup(LINK(ircs)->connect_nick);
	}

	ls_set_nick(ircs, nick);
	WRITE_LINE1(CONN(ircs), NULL, "NICK", ircs->nick);
}

static void server_next(struct link *l)
{
	l->cur_server++;
	if (l->cur_server >= l->network->serverc)
		l->cur_server = 0;
}

static struct link_client *irc_accept_new(connection_t *conn)
{
	struct link_client *ircc;
	connection_t *newconn;

	newconn = accept_new(conn);
	if (!newconn)
		return NULL;

	ircc = bip_calloc(sizeof(struct link_client), (size_t)1);
	CONN(ircc) = newconn;
	TYPE(ircc) = IRC_TYPE_LOGGING_CLIENT;
	CONN(ircc)->user_data = ircc;
	return ircc;
}

void server_cleanup(struct link_server *server)
{
	if (server->nick) {
		free(server->nick);
		server->nick = NULL;
	}
	if (LINK(server)->s_state == IRCS_CONNECTED) {
		LINK(server)->s_state = IRCS_WAS_CONNECTED;
	} else {
		struct line *s;
		LINK(server)->s_state = IRCS_NONE;
		while ((s = list_remove_first(&LINK(server)->init_strings)))
			irc_line_free(s);
	}

	hash_iterator_t hi;
	for (hash_it_init(&server->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi))
		channel_free(hash_it_item(&hi));
	hash_clean(&server->channels);

	if (CONN(server)) {
		connection_free(CONN(server));
		CONN(server) = NULL;
	}
	irc_lag_init(server);
}

void irc_client_close(struct link_client *ic)
{
	if (TYPE(ic) == IRC_TYPE_CLIENT) {
		struct link_server *is = LINK(ic)->l_server;
		log_client_disconnected(LINK(ic)->log);
		unbind_from_link(ic);
		if (LINK(ic)->l_clientc == 0) {
			if (is && LINK(ic)->away_nick)
				WRITE_LINE1(CONN(is), NULL, "NICK",
						LINK(ic)->away_nick);
			if (is && LINK(ic)->no_client_away_msg)
				WRITE_LINE1(CONN(is), NULL, "AWAY",
						LINK(ic)->no_client_away_msg);
			log_client_none_connected(LINK(ic)->log);
		}
		irc_client_free(ic);
	} else if (TYPE(ic) == IRC_TYPE_TRUST_CLIENT) {
		unbind_from_link(ic);
		irc_client_free(ic);
	} else if (TYPE(ic) == IRC_TYPE_LOGGING_CLIENT) {
		irc_client_free(ic);
	}
}

static void server_setup_reconnect_timer(struct link *link)
{
	int timer = 0;

	if (link->last_connection_attempt &&
			time(NULL) - link->last_connection_attempt
				< CONN_INTERVAL) {
		timer = conf_reconn_timer * (link->s_conn_attempt);
		if (timer > RECONN_TIMER_MAX)
			timer = RECONN_TIMER_MAX;
	}
	mylog(LOG_ERROR, "[%s] reconnecting in %d seconds", link->name,
			timer);
	link->recon_timer = timer;
}

static void irc_close(struct link_any *l)
{
	if (CONN(l)) {
		connection_free(CONN(l));
		CONN(l) = NULL;
	}
	if (TYPE(l) == IRC_TYPE_SERVER) {
		/* TODO: free link_server as a whole */
		struct link_server *is = (struct link_server *)l;

		if (LINK(is)->s_state == IRCS_CONNECTED)
			irc_notify_disconnection(is);
		irc_server_shutdown(is);
		log_disconnected(LINK(is)->log);

		server_next(LINK(is));
		server_cleanup(is);
		server_setup_reconnect_timer(LINK(is));

		LINK(is)->l_server = NULL;
		irc_server_free((struct link_server *)is);
	} else {
		irc_client_close((struct link_client *)l);
	}
}

struct link_client *irc_client_new(void)
{
	struct link_client *c;

	c = bip_calloc(sizeof(struct link_client), (size_t)1);
	list_init(&c->who_queue, list_ptr_cmp);

	return c;
}

struct link_server *irc_server_new(struct link *link, connection_t *conn)
{
	struct link_server *s;

	s = bip_calloc(sizeof(struct link_server), (size_t)1);

	TYPE(s) = IRC_TYPE_SERVER;
	hash_init(&s->channels, HASH_NOCASE);

	link->l_server = s;
	LINK(s) = link;
	CONN(s) = conn;

	irc_lag_init(s);
	array_init(&s->chanmodes);
	s->prefixes = NULL;
	s->usermodes = NULL;
	server_init_modes(s);

	return s;
}

static void server_init_modes(struct link_server *s)
{
	// Default values used if CHANMODES is not specified by the server
	array_push(&s->chanmodes, bip_strdup("beHIq"));
	array_push(&s->chanmodes, bip_strdup("k"));
	array_push(&s->chanmodes, bip_strdup("fjl"));
	array_push(&s->chanmodes, bip_strdup("fjl"));

	// Default values used if prefix is not specified by the server
	s->prefixes = bip_realloc(s->prefixes, sizeof(*s->prefixes) * 3);
	s->usermodes = bip_realloc(s->usermodes, sizeof(s->usermodes) * 3);
	strcpy(s->prefixes, "@+");
	strcpy(s->usermodes, "ov");
}

void irc_server_free(struct link_server *s)
{
	if (CONN(s))
		connection_free(CONN(s));
	if (s->nick)
		free(s->nick);
	if (s->user_mode)
		free(s->user_mode);

	int i;
	char *ptr;
	array_each(&s->chanmodes, i, ptr)
		free(ptr);

	MAYFREE(s->prefixes);
	MAYFREE(s->usermodes);

	hash_iterator_t hi;
	for (hash_it_init(&s->channels, &hi); hash_it_item(&hi);
			hash_it_next(&hi)) {
		struct channel *chan = hash_it_item(&hi);
		channel_free(chan);
	}
	hash_clean(&s->channels);

	free(s);
}

connection_t *irc_server_connect(struct link *link)
{
	struct link_server *ls;
	connection_t *conn;

	link->s_conn_attempt++;

	mylog(LOG_INFO, "[%s] Connecting user '%s' using server "
		"%s:%d", link->name, link->user->name,
		link->network->serverv[link->cur_server].host,
		link->network->serverv[link->cur_server].port);
	conn = connection_new(link->network->serverv[link->cur_server].host,
				link->network->serverv[link->cur_server].port,
				link->vhost, link->bind_port,
#ifdef HAVE_LIBSSL
				link->network->ssl,
				link->network->ciphers,
				link->ssl_check_mode,
				link->user->ssl_check_store,
				link->user->ssl_client_certfile,
#else
				0, NULL, 0, NULL, NULL,
#endif
				CONNECT_TIMEOUT);
	assert(conn);
	if (conn->handle == -1) {
		mylog(LOG_INFO, "[%s] Cannot connect.", link->name);
		connection_free(conn);
		server_next(link);
		return NULL;
	}

	ls = irc_server_new(link, conn);
	conn->user_data = ls;

	list_add_last(&_bip->conn_list, conn);
	oidentd_dump(_bip);

	if (link->sasl_mechanism) {
		mylog(LOG_INFO, "[%s] SASL (%s) enabled, sending CAP REQ.",
			link->name, sasl_mechanism_to_text(link->sasl_mechanism));
		WRITE_LINE2(conn, NULL, "CAP", "REQ", ":sasl");
	}
	irc_server_startup(ls);
	return conn;
}

int irc_server_lag_compute(struct link *l)
{
	struct link_server *server = l->l_server;

	if (LINK(server)->s_state == IRCS_CONNECTED) {
		if (server->laginit_ts != -1) {
			irc_compute_lag(server);
			if (!irc_lags_out(server))
				return 0;
			return 1;
		} else {
			server->lagtest_timeout--;
			if (server->lagtest_timeout == 0)
				irc_start_lagtest(server);
		}
	}
	return 0;
}

void irc_server_shutdown(struct link_server *s)
{
	int i;
	char *cur;
	array_each(&s->chanmodes, i, cur)
		free(cur);
	array_deinit(&s->chanmodes);

	server_init_modes(s);

	if (!s->nick)
		return;
	if (LINK(s)->prev_nick)
		free(LINK(s)->prev_nick);
	LINK(s)->prev_nick = bip_strdup(s->nick);
}

#define BIP_OIDENTD_START "## AUTOGENERATED BY BIP. DO NOT EDIT ##\n"
#define BIP_OIDENTD_END "## END OF AUTOGENERATED STUFF ##\n"
#define BIP_OIDENTD_END_LENGTH strlen(BIP_OIDENTD_END)

void oidentd_dump(bip_t *bip)
{
	mylog(LOG_ERROR, "%d %s", bip->write_oidentd, bip->oidentdpath);
	if (!bip->write_oidentd || bip->oidentdpath == NULL) {
		return;
	}
	list_iterator_t it;
	FILE *f;
	char *bipstart = NULL, *bipend = NULL;
	struct stat stats;
	char tag_written = 0;

	if (stat(bip->oidentdpath, &stats) == -1) {
		if (errno == ENOENT && (f = fopen(bip->oidentdpath, "w+"))) {
			fchmod(fileno(f), 0644);
		} else {
			mylog(LOG_WARN, "Can't open/create %s",
					bip->oidentdpath);
			return;
		}
	} else {
		/* strip previously autogenerated content */
		char *content;
		f = fopen(bip->oidentdpath, "r+");

		if (!f) {
			mylog(LOG_WARN, "Can't open/create %s",
					bip->oidentdpath);
			return;
		}

		content = (char *)bip_malloc(stats.st_size + 1);

		if (fread(content, (size_t)1, stats.st_size, f) !=
				(size_t)stats.st_size) {
			mylog(LOG_WARN, "Can't read %s fully",
					bip->oidentdpath);
			free(content);
			goto clean_oidentd;
		}

		/* Set terminating zero for strstr */
		content[stats.st_size] = '\0';

		bipstart = strstr(content, BIP_OIDENTD_START);
		if (bipstart != NULL) {
			// We have some config left, rewrite the file completely
			fseek(f, (long)SEEK_SET, (int)0);
			if (ftruncate(fileno(f), (off_t)0) == -1) {
				mylog(LOG_DEBUG, "Can't reset %s size",
						bip->oidentdpath);
				free(content);
				goto clean_oidentd;
			}

			bipend = strstr(bipstart, BIP_OIDENTD_END);

			/* data preceeding the tag */
			fwrite(content, 1, bipstart - content, f);

			/* data following the tag, if any */
			if (bipend != NULL)
				fwrite(bipend + BIP_OIDENTD_END_LENGTH, 1,
						stats.st_size -
						(bipend - content) -
						BIP_OIDENTD_END_LENGTH, f);
			else
				mylog(LOG_WARN, "No %s mark found in %s",
						BIP_OIDENTD_END,
						bip->oidentdpath);
		} else {
			/* No previous conf */
			if (stats.st_size != 0 &&
					content[stats.st_size - 1] != '\n')
				fprintf(f, "\n");
		}
		free(content);
	}

	for (list_it_init(&bip->conn_list, &it); list_it_item(&it);
			list_it_next(&it)) {
		connection_t *c = list_it_item(&it);
		struct link_any *la = c->user_data;
		if (la && TYPE(la) == IRC_TYPE_SERVER && (
				c->connected == CONN_OK ||
				c->connected == CONN_NEED_SSLIZE ||
				c->connected == CONN_UNTRUSTED)) {
			struct link_server *ls;
			struct link *l;

			if (!tag_written) {
				fprintf(f, BIP_OIDENTD_START);
				tag_written = 1;
			}

			ls = (struct link_server*)la;
			l = LINK(ls);

			fprintf(f, "to %s fport %d from %s lport %d {\n",
					c->remoteip, c->remoteport, c->localip,
					c->localport);
			fprintf(f, "\treply \"%s\"\n", l->username);
			fprintf(f, "}\n");
		}
	}
	if (tag_written)
		fprintf(f, BIP_OIDENTD_END);

clean_oidentd:
	fclose(f);
}

void timeout_clean_who_counts(list_t *conns)
{
	list_iterator_t it;
	for (list_it_init(conns, &it); list_it_item(&it); list_it_next(&it)) {
		struct link *l = list_it_item(&it);
		struct link_client *client = l->who_client;

		if (client && client->whoc_tstamp) {
			time_t now;
			now = time(NULL);
			if (now - client->whoc_tstamp > 10) {
				mylog(LOG_DEBUG, "Yawn, "
						"forgetting one who reply");
				if (client->who_count > 0)
					--client->who_count;
				client->whoc_tstamp = time(NULL);
				if (client->who_count == 0)
					rotate_who_client(l);
			}
		}
	}
}

void bip_init(bip_t *bip)
{
	memset(bip, 0, sizeof(bip_t));
	list_init(&bip->link_list, list_ptr_cmp);
	list_init(&bip->conn_list, list_ptr_cmp);
	list_init(&bip->connecting_client_list, list_ptr_cmp);

	hash_init(&bip->users, HASH_NOCASE);
	hash_init(&bip->networks, HASH_NOCASE);
}

/* Called each second. */
void bip_tick(bip_t *bip)
{
	static int logflush_timer = 0;
	struct link *link;
	list_iterator_t li;

	/* log flushs */
	if (logflush_timer-- <= 0) {
		logflush_timer = conf_log_sync_interval;
		log_flush_all();
	}

	/* handle tick for links: detect lags or start a reconnection */
	for (list_it_init(&bip->link_list, &li); (link = list_it_item(&li));
			list_it_next(&li)) {
		if (link->l_server) {
			if (irc_server_lag_compute(link)) {
				log_ping_timeout(link->log);
				list_remove(&bip->conn_list,
						CONN(link->l_server));
				irc_close((struct link_any *) link->l_server);
			}
		} else {
			if (link->recon_timer == 0) {
				connection_t *conn;
				link->last_connection_attempt = time(NULL);
				conn = irc_server_connect(link);
				if (!conn)
					server_setup_reconnect_timer(link);
			} else {
				link->recon_timer--;
			}
		}
	}

	/* drop lagging connecting client */
	for (list_it_init(&bip->connecting_client_list, &li); list_it_item(&li);
			list_it_next(&li)) {
		struct link_client *ic = list_it_item(&li);
		ic->logging_timer++;
		if (ic->logging_timer > LOGGING_TIMEOUT) {
			if (CONN(ic))
				list_remove(&bip->conn_list, CONN(ic));
			irc_close((struct link_any *)ic);
			list_it_remove(&li);
		}
	}

	/*
	 * Cleanup lagging or dangling who_count buffers
	 */
	timeout_clean_who_counts(&bip->link_list);
}

void bip_on_event(bip_t *bip, connection_t *conn)
{
	struct link_any *lc = (struct link_any *)conn->user_data;

	if (conn == bip->listener) {
		struct link_client *n = irc_accept_new(conn);
		if (n) {
			list_add_last(&bip->conn_list, CONN(n));
			list_add_last(&bip->connecting_client_list, n);
		}
		return;
	}

	/* reached only if socket is not listening */
	int err;
	list_t *linel = read_lines(conn, &err);
	if (err) {
		if (TYPE(lc) == IRC_TYPE_SERVER) {
			mylog(LOG_ERROR, "[%s] read_lines error, closing...",
					link_name(lc));
			irc_server_shutdown(LINK(lc)->l_server);
		} else {
			mylog(LOG_ERROR, "client read_lines error, closing...");
		}
		goto prot_err;
	}
	if (!linel)
		return;

	char *line_s;
	while ((line_s = list_remove_first(linel))) {
		struct line *line;
		mylog(LOG_DEBUG, "\"%s\"", line_s);
		if (*line_s == 0) { /* irssi does that.*/
			free(line_s);
			continue;
		}

		line = irc_line_new_from_string(line_s);
		if (!line) {
			mylog(LOG_ERROR, "[%s] Can not parse line. Link type: %d. "
					"closing...", link_name(lc), TYPE(lc));
			free(line_s);
			goto prot_err_lines;
		}
		int r;
		r = irc_dispatch(bip, lc, line);
		irc_line_free(line);
		free(line_s);
		if (r == ERR_PROTOCOL) {
			mylog(LOG_ERROR, "[%s] Error in protocol. Link type: %d closing...",
					link_name(lc), TYPE(lc));
			goto prot_err_lines;
		}
		if (r == ERR_AUTH)
			goto prot_err_lines;
		/* XXX: not real error */
		if (r == OK_CLOSE)
			goto prot_err_lines;

	}
	list_free(linel);
	return;
prot_err_lines:
	while ((line_s = list_remove_first(linel)))
		free(line_s);
prot_err:
	list_remove(&bip->conn_list, conn);
	if (linel)
		list_free(linel);
	if (lc) {
		if (TYPE(lc) == IRC_TYPE_LOGGING_CLIENT || TYPE(lc) ==
				IRC_TYPE_TRUST_CLIENT)
			list_remove(&bip->connecting_client_list, lc);
		irc_close(lc);
	}
}

/*
 * The main loop
 * inc is the incoming connection, clientl list a list of client struct that
 * represent the accepcted credentials
 */
void irc_main(bip_t *bip)
{
	int timeleft = 1000;

	if (bip->reloading_client) {
		char *l;

		while ((l = list_remove_first(&bip->errors)))
			bip_notify(bip->reloading_client, "%s", l);
		bip->reloading_client = NULL;
	}

	/*
	 * If the list is empty, we are starting. Otherwise we are reloading,
	 * and conn_list is kept accross reloads.
	 */
	if (list_is_empty(&bip->conn_list))
		list_add_first(&bip->conn_list, bip->listener);

	while (!sighup) {
		connection_t *conn;

		if (timeleft == 0) {
			/*
			 * Compute timeouts for next reconnections and lagouts
			 */

			timeleft = 1000;
			bip_tick(bip);
		}

		int nc;
		/* Da main loop */
		list_t *ready = wait_event(&bip->conn_list, &timeleft, &nc);
		if (nc)
			oidentd_dump(bip);
		while ((conn = list_remove_first(ready)))
			bip_on_event(bip, conn);
		list_free(ready);
	}
	while (list_remove_first(&bip->connecting_client_list))
		;
	return;
}

void irc_client_free(struct link_client *cli)
{
	if (CONN(cli))
		connection_free(CONN(cli));
	if (cli->init_pass)
		free(cli->init_pass);
	if (cli->init_nick)
		free(cli->init_nick);
	free(cli);
}

struct link *irc_link_new(void)
{
	struct link *link;
	link = bip_calloc(sizeof(struct link), (size_t)1);

	link->l_server = NULL;
	hash_init(&link->chan_infos, HASH_NOCASE);
	list_init(&link->chan_infos_order, list_ptr_cmp);
	list_init(&link->on_connect_send, list_ptr_cmp);
	link->autojoin_on_kick = 1;
	link->ignore_server_capab = 1;
	return link;
}

void link_kill(bip_t *bip, struct link *link)
{
	/* in case in never got connected */
	if (link->l_server) {
		list_remove(&bip->conn_list, CONN(link->l_server));
		server_cleanup(link->l_server);
		irc_server_free(link->l_server);
	}
	while (link->l_clientc) {
		struct link_client *lc = link->l_clientv[0];
		if (lc == bip->reloading_client)
			bip->reloading_client = NULL;
		list_remove(&bip->conn_list, CONN(lc));
		unbind_from_link(lc);
		irc_client_free(lc);
	}

	hash_remove(&link->user->connections, link->name);
	free(link->name);
	log_free(link->log);
	MAYFREE(link->prev_nick);
	MAYFREE(link->cli_nick);

	void *p;
	while ((p = list_remove_first(&link->init_strings)))
		free(p);
	while ((p = list_remove_first(&link->on_connect_send)))
		free(p);
	MAYFREE(link->no_client_away_msg);
	MAYFREE(link->away_nick);
	hash_clean(&link->chan_infos);

	struct chan_infos *ci;
	while ((ci = list_remove_first(&link->chan_infos_order)))
		free(ci);

	list_remove(&bip->link_list, link);

	MAYFREE(link->username);
	MAYFREE(link->realname);
	MAYFREE(link->s_password);
	MAYFREE(link->sasl_username);
	MAYFREE(link->sasl_password);
	MAYFREE(link->connect_nick);
	MAYFREE(link->vhost);
#ifdef HAVE_LIBSSL
	sk_X509_free(link->untrusted_certs);
#endif
	free(link);
}

static void server_set_chanmodes(struct link_server *l, const char *modes)
{
	int i;
	char *cur;
	char *dup;

	mylog(LOG_DEBUG, "[%s] Set chanmodes", LINK(l)->name);

	array_each(&l->chanmodes, i, cur)
		free(cur);
	array_deinit(&l->chanmodes);

	// handle four categories, ignore all others
	for (i = 0; i < 4; i++) {
		cur = strchr(modes, ',');
		if (cur || modes) {
			size_t len;
			if (cur)
				len = cur - modes;
			else
				len = strlen(modes); // last piece
			dup = bip_malloc(len + 1);
			memcpy(dup, modes, len);
			dup[len] = 0;
			modes = cur + 1;
		} else {
			// emptry string
			dup = bip_calloc((size_t)1, sizeof(char));
		}
		mylog(LOG_DEBUGVERB, "[%s] Modes: '%s'", LINK(l)->name, dup);
		array_push(&l->chanmodes, dup);
	}
}


static void server_set_prefix(struct link_server *s, const char *modes)
{
	char * end_mode;
	unsigned int len;

	mylog(LOG_DEBUG, "[%s] Set user modes", LINK(s)->name);

	// PREFIX=(mode)prefix

	end_mode = strchr(modes + 1, ')'); // skip '('
	if (*modes != '(' || !end_mode) {
		mylog(LOG_WARN, "[%s] Unable to parse PREFIX parameter", LINK(s)->name);
		return;
	}

	len = end_mode - modes - 1; // len of mode without '('
	if (len * 2 + 2 != strlen(modes)) {
		mylog(LOG_WARN, "[%s] Unable to parse PREFIX parameter", LINK(s)->name);
		return;
	}

	s->prefixes = bip_realloc(s->prefixes, sizeof(*s->prefixes) * (len + 1));
	s->usermodes = bip_realloc(s->usermodes, sizeof(s->usermodes) * (len + 1));

	memcpy(s->usermodes, modes + 1, len);
	s->usermodes[len] = 0;
	memcpy(s->prefixes, end_mode + 1, len);
	s->prefixes[len] = 0;

	mylog(LOG_DEBUGVERB, "[%s] user prefix: '%s'", LINK(s)->name, s->prefixes);
	mylog(LOG_DEBUGVERB, "[%s] user modes: '%s'", LINK(s)->name, s->usermodes);
}

// Return the position (*1 based*) of car in str, else -1
static int bip_get_index(const char* str, char car)
{
	char *cur;
	if ((cur = strchr(str, car)))
		return cur - str + 1;
	else
		return 0;
}

static int bip_fls(int v)
{
	unsigned int r = 0;
	while (v >>= 1)
		r++;

	return r;
}
