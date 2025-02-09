%option nounput noinput
%{
/*
 * $Id: lex.l,v 1.23 2005/04/12 19:34:35 nohar Exp $
 *
 * This file is part of the bip proproject
 * Copyright (C) 2004 Arnaud Cornet
 * Copyright (C) 2022 Loïc Gomez
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "conf.h"
int linec;
#include "util.h"
extern list_t *root_list;
extern int yyparse(void);
void free_conf(list_t*);
int conf_error;
typedef struct bip bip_t;
extern bip_t *_bip;

void conf_die(bip_t *, char *, ...);

int yyerror(char *err)
{
	conf_die(_bip, "Parse error '%s' near '%s', line %d", err, yytext,
		linec + 1);
	conf_error = 1;
	return 1;
}

list_t *parse_conf(FILE *file, int *err)
{
	conf_error = 0;
	linec = 0;

	YY_BUFFER_STATE in = yy_create_buffer(file, YY_BUF_SIZE);
	yy_switch_to_buffer(in);
	yyparse();
	yy_delete_buffer(in);
	*err = conf_error;
	return root_list;
}
%}
%%
(" "|\t)+
\n                      { linec++; }
"#"[^\n]*$
[0-9]+			{
				yylval.number = atoi(yytext);
				return LEX_INT;
			}
("true"|"false")	{
				yylval.number = strcmp(yytext, "true")
				== 0 ? 1 : 0;
				return LEX_BOOL;
			}
"ip"			{ return LEX_IP; }
"port"			{ return LEX_PORT; }
"client_side_ssl"	{ return LEX_CSS; }
"server"		{ return LEX_SERVER; }
"network"		{ return LEX_NETWORK; }
"host"			{ return LEX_HOST; }
"name"			{ return LEX_NAME; }
"user"			{ return LEX_USER; }
"admin"			{ return LEX_ADMIN; }
"connection"		{ return LEX_CONNECTION; }
"nick"			{ return LEX_NICK; }
"realname"		{ return LEX_REALNAME; }
"default_nick"		{ return LEX_DEFAULT_NICK; }
"default_user"		{ return LEX_DEFAULT_USER; }
"default_realname"	{ return LEX_DEFAULT_REALNAME; }
"source_port"		{ return LEX_SOURCE_PORT; }
"vhost"			{ return LEX_VHOST; }
"password"		{ return LEX_PASSWORD; }
"ssl"		        { return LEX_SSL; }
"ssl_check_mode"        { return LEX_SSL_CHECK_MODE; }
"ssl_check_store"       { return LEX_SSL_CHECK_STORE; }
"ssl_client_certfile"   { return LEX_SSL_CLIENT_CERTFILE; }
"ssl_default_ciphers"	{ return LEX_DEFAULT_CIPHERS; }
"ciphers"		{ return LEX_CIPHERS; }
"key"			{ return LEX_KEY; }
"autojoin_on_kick"	{ return LEX_AUTOJOIN_ON_KICK; }
"channel"		{ return LEX_CHANNEL; }
"log_level"		{ return LEX_LOG_LEVEL; }
"log_root"		{ return LEX_LOG_ROOT; }
"log_format"		{ return LEX_LOG_FORMAT; }
"backlog_lines"		{ return LEX_BACKLOG_LINES; }
"backlog_timestamp"		{ return LEX_BACKLOG_TIMESTAMP; }
"backlog_no_timestamp"		{ return LEX_BACKLOG_NO_TIMESTAMP; }
"backlog"		{ return LEX_BACKLOG; }
"backlog_always"	{ return LEX_ALWAYS_BACKLOG; }
"backlog_msg_only"	{ return LEX_BL_MSG_ONLY; }
"backlog_reset_on_talk"	{ return LEX_BLRESET_ON_TALK; }
"backlog_reset_connection"	{ return LEX_BLRESET_CONNECTION; }
"blreset_on_talk"	{ return LEX_BLRESET_ON_TALK; }
"bl_msg_only"		{ return LEX_BL_MSG_ONLY; }
"always_backlog"	{ return LEX_ALWAYS_BACKLOG; }
"log"			{ return LEX_LOG; }
"log_system"		{ return LEX_LOG_SYSTEM; }
"log_sync_interval"	{ return LEX_LOG_SYNC_INTERVAL; }
"follow_nick"		{ return LEX_FOLLOW_NICK; }
"ignore_first_nick"	{ return LEX_IGN_FIRST_NICK; }
"away_nick"		{ return LEX_AWAY_NICK; }
"on_connect_send"	{ return LEX_ON_CONNECT_SEND; }
"no_client_away_msg"	{ return LEX_NO_CLIENT_AWAY_MSG; }
"pid_file"		{ return LEX_PID_FILE; }
"write_oidentd"		{ return LEX_WRITE_OIDENTD; }
"oidentd_file"		{ return LEX_OIDENTD_FILE; }
"bip_use_notice"	{ return LEX_BIP_USE_NOTICE; }
"client_side_ssl_pem"	{ return LEX_CSS_PEM; }
"client_side_ciphers"	{ return LEX_CSS_CIPHERS; }
"client_side_dh_param"	{ return LEX_DH_PARAM; }
"sasl_username"	{ return LEX_SASL_USERNAME; }
"sasl_password"	{ return LEX_SASL_PASSWORD; }
"sasl_mechanism"	{ return LEX_SASL_MECHANISM; }
"ignore_server_capab"	{ return LEX_IGNORE_CAPAB; }
"reconn_timer"		{ return LEX_RECONN_TIMER; }
\"[^"]*\" 		{
				size_t len = strlen(yytext) - 2;
				yylval.string = bip_malloc(len + 1);
				memcpy(yylval.string, yytext + 1, len);
				yylval.string[len] = 0;
				return LEX_STRING;
			}
"="			{ return LEX_EQ; }
"{"			{ return LEX_LBRA; }
"}"			{ return LEX_RBRA; }
";"			{ return LEX_SEMICOLON; }
.			{ conf_die(_bip, "Parse error in config file line %d, unknown character '%s'", linec + 1, yytext); conf_error = 1;
			return LEX_BUNCH; }
%%
