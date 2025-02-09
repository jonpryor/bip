/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2022 Loïc Gomez
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef BASE64_H
#define BASE64_H

unsigned char *base64_encode(const unsigned char *src, size_t len,
			     size_t *out_len);

#endif /* BASE64_H */
