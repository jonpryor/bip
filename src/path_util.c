/*
 * This file is part of the bip project
 * Copyright (C) 2016 Pierre-Louis Bonicoli
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * See the file "COPYING" for the exact licensing terms.
 */

#include "path_util.h"
#include "util.h"

#include <stdio.h>
#include <string.h>

char *default_path(const char *biphome, const char *filename, const char *desc)
{
	char *conf_file;
	// '/' and \0
	conf_file = bip_malloc(strlen(biphome) + strlen(filename) + 2);
	strcpy(conf_file, biphome);
	conf_file[strlen(biphome)] = '/';
	conf_file[strlen(biphome) + 1] = '\0';
	strcat(conf_file, filename);
	mylog(LOG_INFO, "Default %s: %s", desc, conf_file);
	return conf_file;
}

void assert_path_exists(char *path)
{
	FILE* f;
	if ((f = fopen(path, "r")) == NULL)
		fatal("Unable to open file %s for reading", path);
	else
		fclose(f);
}
