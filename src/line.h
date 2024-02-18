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

#ifndef IRC_LINE_H
#define IRC_LINE_H

#include "connection.h"

#define WRITE_LINE0(con, org, com)                                             \
	do {                                                                   \
		struct line l;                                                 \
		irc_line_init(&l);                                             \
		l.origin = org;                                                \
		_irc_line_append(&l, com);                                     \
		irc_line_write(&l, con);                                       \
		_irc_line_deinit(&l);                                          \
	} while (0)

#define WRITE_LINE1(con, org, com, a)                                          \
	do {                                                                   \
		struct line l;                                                 \
		irc_line_init(&l);                                             \
		l.origin = org;                                                \
		_irc_line_append(&l, com);                                     \
		_irc_line_append(&l, a);                                       \
		irc_line_write(&l, con);                                       \
		_irc_line_deinit(&l);                                          \
	} while (0)

#define WRITE_LINE2(con, org, com, a1, a2)                                     \
	do {                                                                   \
		struct line l;                                                 \
		irc_line_init(&l);                                             \
		l.origin = org;                                                \
		_irc_line_append(&l, com);                                     \
		_irc_line_append(&l, a1);                                      \
		_irc_line_append(&l, a2);                                      \
		irc_line_write(&l, con);                                       \
		_irc_line_deinit(&l);                                          \
	} while (0)

#define WRITE_LINE3(con, org, com, a1, a2, a3)                                 \
	do {                                                                   \
		struct line l;                                                 \
		irc_line_init(&l);                                             \
		l.origin = org;                                                \
		_irc_line_append(&l, com);                                     \
		_irc_line_append(&l, a1);                                      \
		_irc_line_append(&l, a2);                                      \
		_irc_line_append(&l, a3);                                      \
		irc_line_write(&l, con);                                       \
		_irc_line_deinit(&l);                                          \
	} while (0)

#define WRITE_LINE4(con, org, com, a1, a2, a3, a4)                             \
	do {                                                                   \
		struct line l;                                                 \
		irc_line_init(&l);                                             \
		l.origin = org;                                                \
		_irc_line_append(&l, com);                                     \
		_irc_line_append(&l, a1);                                      \
		_irc_line_append(&l, a2);                                      \
		_irc_line_append(&l, a3);                                      \
		_irc_line_append(&l, a4);                                      \
		irc_line_write(&l, con);                                       \
		_irc_line_deinit(&l);                                          \
	} while (0)

struct line {
	char *origin;
	array_t words;
	int colon;
};

void irc_line_init(struct line *l);
void _irc_line_deinit(struct line *l);
struct line *irc_line_new(void);
void irc_line_write(struct line *l, connection_t *c);
void irc_line_append(struct line *l, const char *s);
struct line *irc_line_new_from_string(char *str);
char *irc_line_to_string(struct line *l);
char *irc_line_to_string_to(struct line *line, char *nick);
void irc_line_free(struct line *l);
struct line *irc_line_dup(struct line *line);
void _irc_line_append(struct line *l, const char *s);
int irc_line_includes(struct line *line, int elem);
const char *irc_line_elem(struct line *line, int elem);
int irc_line_count(struct line *line);
char *irc_line_pop(struct line *l);
int irc_line_is_error(struct line *line);
int irc_line_elem_equals(struct line *line, int elem, const char *cmp);
int irc_line_elem_case_equals(struct line *line, int elem, const char *cmp);
void irc_line_drop(struct line *line, int elem);

#endif
