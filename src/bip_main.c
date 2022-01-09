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
#define OIDENTD_FILENAME ".oidentd.conf"

extern int sighup;
extern char *conf_log_root;
extern char *conf_log_format;
extern int conf_log_level;
extern char *conf_ip;
extern unsigned short conf_port;
extern int conf_css;
#ifdef HAVE_LIBSSL
extern char *conf_ssl_certfile;
extern char *conf_client_ciphers;
extern char *conf_client_dh_file;
extern char *conf_server_default_ciphers;
#endif
extern int conf_daemonize;
extern char *conf_pid_file;
extern char *conf_biphome;
extern int conf_reconn_timer;

/* log options, for sure the trickiest :) */
extern int conf_log;
extern int conf_log_system;
extern int conf_log_sync_interval;
extern bip_t *_bip;
extern FILE *conf_global_log_file;

void reload_config(int i);
void bad_quit(int i);
void check_rlimits(void);
void rlimit_cpu_reached(int i);
void rlimit_bigfile_reached(int i);
void conf_die(bip_t *bip, char *fmt, ...);
int fireup(bip_t *bip, FILE *conf);
int do_pid_stuff(void);

static void usage(char *name)
{
	printf(
"Usage: %s [-f config_file] [-h] [-n]\n"
"	-f config_file: Use config_file as the configuration file\n"
"		If no config file is given %s will try to open ~/.bip/" S_CONF "\n"
"	-n: Don't daemonize, log in stderr\n"
"	-s: Bip HOME, default parent directory for client certificate,\n"
"		configuration, logs, pid, oidentd\n"
"	-v: Print version and exit\n"
"	-h: This help\n", name, name);
	exit(1);
}

static void version(void)
{
	printf(
"Bip IRC Proxy - " PACKAGE_VERSION "\n"
"Copyright © Arnaud Cornet and Loïc Gomez (2004 - 2008)\n"
"Distributed under the GNU General Public License Version 2\n");
}

static void log_file_setup(void)
{
	char buf[4096];

	if (conf_log_system && conf_daemonize) {
		if (conf_global_log_file && conf_global_log_file != stderr)
			fclose(conf_global_log_file);
		snprintf(buf, (size_t) 4095, "%s/bip.log", conf_log_root);
		FILE *f = fopen(buf, "a");
		if (!f)
			fatal("Can't open %s: %s", buf, strerror(errno));
		conf_global_log_file = f;
	} else {
		conf_global_log_file = stderr;
	}
}

static pid_t daemonize(void)
{
	switch (fork()) {
	case -1:
		fatal("Fork failed");
		break;
	case 0:
		break;
	default:
		_exit(0);
	}

	if (setsid() < 0)
		fatal("setsid() failed");

	switch (fork()) {
	case -1:
		fatal("Fork failed");
		break;
	case 0:
		break;
	default:
		_exit(0);
	}

	close(0);
	close(1);
	close(2);
	/* This better be the very last action since fatal makes use of
	 * conf_global_log_file */
	return getpid();
}

int main(int argc, char **argv)
{
	FILE *conf = NULL;
	char *confpath = NULL;
	int ch;
	int r, fd;
	char buf[30];
	bip_t bip;

	bip_init(&bip);
	_bip = &bip;

	conf_ip = bip_strdup("0.0.0.0");
	conf_port = 7778;
	conf_css = 0;

	signal(SIGPIPE, SIG_IGN);
	signal(SIGHUP, reload_config);
	signal(SIGINT, bad_quit);
	signal(SIGQUIT, bad_quit);
	signal(SIGTERM, bad_quit);
	signal(SIGXFSZ, rlimit_bigfile_reached);
	signal(SIGXCPU, rlimit_cpu_reached);

	conf_log_root = NULL;
	conf_log_format = bip_strdup(DEFAULT_LOG_FORMAT);
	conf_log_level = DEFAULT_LOG_LEVEL;
	conf_reconn_timer = DEFAULT_RECONN_TIMER;
	conf_daemonize = 1;
	conf_global_log_file = stderr;
	conf_pid_file = NULL;
#ifdef HAVE_LIBSSL
	conf_ssl_certfile = NULL;
	conf_client_ciphers = NULL;
	conf_server_default_ciphers = NULL;
	conf_client_dh_file = NULL;
#endif

	while ((ch = getopt(argc, argv, "hvnf:s:")) != -1) {
		switch (ch) {
		case 'f':
			confpath = bip_strdup(optarg);
			break;
		case 'n':
			conf_daemonize = 0;
			break;
		case 's':
			conf_biphome = bip_strdup(optarg);
			break;
		case 'v':
			version();
			exit(0);
			break;
		default:
			version();
			usage(argv[0]);
		}
	}

	umask(0027);

	check_rlimits();

	char *home = NULL; /* oidentd path searching ignores conf_biphome */
	home = getenv("HOME");
	if (!home && !conf_biphome) {
		conf_die(&bip, "no value for environment variable $HOME,"
			"use '-s' parameter");
		return 0;
	}

	if (!conf_biphome) {
		conf_biphome = bip_malloc(strlen(home) + strlen("/.bip") + 1);
		strcpy(conf_biphome, home);
		strcat(conf_biphome, "/.bip");
	}

	if (!bip.oidentdpath) {
		bip.oidentdpath = bip_malloc(strlen(conf_biphome) + 1 +
				strlen(OIDENTD_FILENAME) + 1);
		strcpy(bip.oidentdpath, conf_biphome);
		strcat(bip.oidentdpath, "/");
		strcat(bip.oidentdpath, OIDENTD_FILENAME);
	}

	if (!confpath) {
		confpath = bip_malloc(strlen(conf_biphome) + 1 +
				strlen(S_CONF) + 1);
		strcpy(confpath, conf_biphome);
		strcat(confpath, "/");
		strcat(confpath, S_CONF);
	}
	conf = fopen(confpath, "r");
	if (!conf)
		fatal("config file not found (%s)", confpath);

	r = fireup(&bip, conf);
	fclose(conf);
	if (!r)
		fatal("Not starting: error in config file.");

	if (!conf_log_root) {
		char *ap = "/logs";
		conf_log_root = bip_malloc(strlen(conf_biphome) +
				strlen(ap) + 1);
		strcpy(conf_log_root, conf_biphome);
		strcat(conf_log_root, ap);
		mylog(LOG_INFO, "Default log root: %s", conf_log_root);
	}
	if (!conf_pid_file) {
		char *pid = "/bip.pid";
		conf_pid_file = bip_malloc(strlen(conf_biphome) +
				strlen(pid) + 1);
		strcpy(conf_pid_file, conf_biphome);
		strcat(conf_pid_file, pid);
		mylog(LOG_INFO, "Default pid file: %s", conf_pid_file);
	}

#ifdef HAVE_LIBSSL
	if (conf_css) {
		int e;
		struct stat fs;

		if (!conf_ssl_certfile) {
			conf_ssl_certfile = default_path(conf_biphome, "bip.pem",
					"SSL certificate");
		}
		assert_path_exists(conf_ssl_certfile);

		e = stat(conf_ssl_certfile, &fs);
		if (e)
			mylog(LOG_WARN, "Unable to check PEM file, stat(%s): "
				"%s", conf_ssl_certfile, strerror(errno));
		else if ((fs.st_mode & S_IROTH) | (fs.st_mode & S_IWOTH))
			mylog(LOG_ERROR, "PEM file %s should not be world "
				"readable / writable. Please fix the modes.",
				conf_ssl_certfile);

		if (conf_client_dh_file) {
			assert_path_exists(conf_client_dh_file);
		}
	}
#endif

	check_dir(conf_log_root, 1);
	fd = do_pid_stuff();
	pid_t pid = 0;

	log_file_setup();
	if (conf_daemonize)
		pid = daemonize();
	else
		pid = getpid();
	snprintf(buf, (size_t) 29, "%lu\n", (unsigned long int)pid);
	ssize_t written;
	written = write(fd, buf, strlen(buf));
	if (written <= 0)
		mylog(LOG_ERROR, "Could not write to PID file");
	close(fd);

	bip.listener = listen_new(conf_ip, conf_port, conf_css);
	if (!bip.listener || bip.listener->connected == CONN_ERROR)
		fatal("Could not create listening socket");

	for (;;) {
		irc_main(&bip);

		sighup = 0;

		conf = fopen(confpath, "r");
		if (!conf)
			fatal("%s config file not found", confpath);
		fireup(&bip, conf);
		fclose(conf);

		/* re-open to allow logfile rotate */
		log_file_setup();
	}
	return 1;
}
