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
#ifndef PATH_UTIL_H
#define PATH_UTIL_H

#include <errno.h>
#include <sys/stat.h>

/* return path of filename located in bip home directory */
char *default_path(const char *biphome, const char *filename, const char *desc);
/* exit program if path doesn't exist */
void assert_path_exists(char *path);

#endif
