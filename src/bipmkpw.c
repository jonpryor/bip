/*
 * $Id$
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
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <fcntl.h>
#include <errno.h>
#include "util.h"
#include "md5.h"

int conf_log_level;
FILE *conf_global_log_file;
int conf_log_system;

void bipmkpw_fatal(char *msg, char *err)
{
	fprintf(stderr, "%s: %s\n", msg, err);
	exit(1);
}

void readpass(char *buffer, int buflen)
{
	int ttyfd = open("/dev/tty", O_RDWR);
	if (ttyfd == -1)
		bipmkpw_fatal("Unable to open tty", strerror(errno));

	struct termios tt, ttback;
	memset(&ttback, 0, sizeof(ttback));
	if (tcgetattr(ttyfd, &ttback) < 0)
		bipmkpw_fatal("tcgetattr failed", strerror(errno));

	memcpy(&tt, &ttback, sizeof(ttback));
// unsigned conversion from ‘int’ to ‘tcflag_t’ {aka ‘unsigned int’} changes value from ‘-11’ to ‘4294967285’
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
	tt.c_lflag &= ~(ICANON|ECHO);
#pragma GCC diagnostic pop
	if (tcsetattr(ttyfd, TCSANOW, &tt) < 0)
		bipmkpw_fatal("tcsetattr failed", strerror(errno));

	if (!write(ttyfd, "Password: ", (size_t)10))
		bipmkpw_fatal("tty write failed", strerror(errno));

	int idx = 0;
	int valid = 1;
	while (idx < buflen) {
		ssize_t rbytes = read(ttyfd, buffer+idx, (size_t)1);
		if (rbytes <= 0) {
			break;
		}
		if (buffer[idx] == '\n') {
			buffer[idx] = 0;
			break;
		} else if (buffer[idx] == ' ') {
			valid = 0;
		}
		idx++;
	}

	if (!write(ttyfd, "\n", (size_t)1))
		bipmkpw_fatal("tty write failed", strerror(errno));

	tcsetattr(ttyfd, TCSANOW, &ttback);
	close(ttyfd);

	if (!valid) {
		fprintf(stderr, "Password cannot contain spaces.\n");
		exit(1);
	}
}

int main(void)
{
	int i;
	static char str[256];
	unsigned char *md5;
	unsigned int seed;

	readpass(str, 256);
	str[255] = 0;

// passing argument 1 of ‘srand’ with different width due to prototype [-Werror=traditional-conversion]
// conversion from ‘time_t’ {aka ‘long int’} to ‘unsigned int’ may change value [-Werror=conversion]
// We don't care.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wtraditional-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
	// the time used to type the pass is entropy
	srand(time(NULL));
#pragma GCC diagnostic pop
	seed = (unsigned)rand(); // rand should be > 0

	md5 = chash_double(str, seed);
        for (i = 0; i < 20; i++)
		printf("%02x", md5[i]);
	printf("\n");
	free(md5);
	return 0;
}
