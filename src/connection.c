/*
 * $Id: connection.c,v 1.98 2005/04/12 19:34:35 nohar Exp $
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
#include <sys/time.h>
#include <time.h>
#include "connection.h"
#include "path_util.h"

extern int errno;
#ifdef HAVE_LIBSSL
static int ssl_initialized = 0;
static SSL_CTX *sslctx = NULL;
static int ssl_cx_idx;
extern FILE *conf_global_log_file;
static BIO *errbio = NULL;
extern char *conf_ssl_certfile;
extern char *conf_biphome;
extern char *conf_client_ciphers;
extern char *conf_client_dh_file;
static int SSLize(connection_t *cn, int *nc);
static SSL_CTX *SSL_init_context(char *ciphers);
/* SSH like trust management */
int link_add_untrusted(void *ls, X509 *cert);
#endif

static int cn_want_write(connection_t *cn);
static int connection_timedout(connection_t *cn);
static int socket_set_nonblock(int s);
static void connection_connected(connection_t *c);

struct connecting_data
{
	struct addrinfo *dst;
	struct addrinfo *src;
	struct addrinfo *cur;
};

static void connecting_data_free(struct connecting_data *t)
{
	if (t->dst)
		freeaddrinfo(t->dst);
	if (t->src)
		freeaddrinfo(t->src);
	free(t);
}

void connection_close(connection_t *cn)
{
	mylog(LOG_DEBUG, "Connection close asked. FD:%d (status: %d)",
			(long)cn->handle, cn->connected);
	if (cn->connected != CONN_DISCONN && cn->connected != CONN_ERROR) {
		cn->connected = CONN_DISCONN;
		if (close(cn->handle) == -1)
			mylog(LOG_WARN, "Error on socket close: %s",
					strerror(errno));
	}
}

void connection_free(connection_t *cn)
{
	connection_close(cn);

	if (cn->outgoing) {
		char *l;
		while ((l = list_remove_first(cn->outgoing)))
			free(l);
		list_free(cn->outgoing);
	}
	if (cn->incoming_lines)
		list_free(cn->incoming_lines);
	if (cn->incoming)
		free(cn->incoming);
	if (cn->connecting_data)
		connecting_data_free(cn->connecting_data);
	/* conn->user_data */
#ifdef HAVE_LIBSSL
	if (cn->ssl) {
		if (cn->cert) {
			X509_free(cn->cert);
			cn->cert = NULL;
		}
		if (cn->ssl_h) {
			SSL_shutdown(cn->ssl_h);
			SSL_free(cn->ssl_h);
			cn->ssl_h = NULL;
		}
		if (cn->ssl_ctx_h) {
			SSL_CTX_free(cn->ssl_ctx_h);
			cn->ssl_ctx_h = NULL;
		}
	}
#endif
	if (cn->localip) {
		free(cn->localip);
		cn->localip = NULL;
	}
	if (cn->remoteip) {
		free(cn->remoteip);
		cn->remoteip = NULL;
	}
	free(cn);
}

static void connect_trynext(connection_t *cn)
{
	struct addrinfo *cur;
	int err;

	if (!cn->connecting_data)
		fatal("called connect_trynext with a connection not "
				"connecting\n");

	cur = cn->connecting_data->cur;

	for (cur = cn->connecting_data->cur ; cur ; cur = cur->ai_next) {
		if ((cn->handle = socket(cur->ai_family, cur->ai_socktype,
						cur->ai_protocol)) < 0) {
			mylog(LOG_WARN, "socket() : %s", strerror(errno));
			continue;
		}

		if (cn->handle >= FD_SETSIZE) {
			mylog(LOG_WARN, "too many fd used, close socket %d",
					cn->handle);

			if (close(cn->handle) == -1)
				mylog(LOG_WARN, "Error on socket close: %s",
						strerror(errno));

			cn->handle = -1;
			break;
		}

		socket_set_nonblock(cn->handle);

		if (cn->connecting_data->src) {
			/* local bind */
			err = bind(cn->handle,
					cn->connecting_data->src->ai_addr,
					cn->connecting_data->src->ai_addrlen);
			if (err == -1)
				mylog(LOG_WARN, "bind() before connect: %s",
						strerror(errno));
		}

		err = connect(cn->handle, cur->ai_addr, cur->ai_addrlen);
		if (err == -1 && errno == EINPROGRESS) {
			/* ok for now, see later */
			/* next time try the next in the list */
			cn->connecting_data->cur = cur->ai_next;
			cn->connect_time = time(NULL);
			cn->connected = CONN_INPROGRESS;
			return;
		}

		if (!err) {
			/* connect() successful */
			connecting_data_free(cn->connecting_data);
			cn->connecting_data = NULL;
			cn->connected = cn->ssl ? CONN_NEED_SSLIZE : CONN_OK;
			connection_connected(cn);
			return;
		}

		/* connect() failed */
		char ip[256];
		mylog(LOG_WARN, "connect(%s) : %s",
			inet_ntop(cur->ai_family, cur->ai_addr, ip, 256),
			strerror(errno));
		close(cn->handle);
		cn->handle = -1;
	}

	cn->connected = CONN_ERROR;
	connecting_data_free(cn->connecting_data);
	cn->connecting_data = NULL;
	mylog(LOG_ERROR, "connect() failed.");
}

#ifdef HAVE_LIBSSL
static X509 *mySSL_get_cert(SSL *ssl)
{
	X509 *cert;

	if (!ssl) {
		mylog(LOG_ERROR, "mySSL_get_cert() No SSL context");
		return NULL;
	}
	cert = SSL_get_peer_certificate(ssl);
	if (cert == NULL)
		mylog(LOG_WARN, "mySSL_get_cert() SSL server supplied no "
				"certificate !");
	return cert;
}

static int _write_socket_SSL(connection_t *cn, char* message)
{
	int count;
	size_t size;

	size = sizeof(char)*strlen(message);

	// let's not ERR (SSL_write doesn't allow 0 len writes)
	if (size == 0)
		return WRITE_OK;

	// this will fail anyways
	if (size > INT_MAX) {
		mylog(LOG_ERROR, "Message too long in SSL write_socket");
		return WRITE_ERROR;
	}

	if (!cn->client && cn->cert == NULL) {
		cn->cert = mySSL_get_cert(cn->ssl_h);
		if (cn->cert == NULL) {
			mylog(LOG_ERROR, "No certificate in SSL write_socket");
			return WRITE_ERROR;
		}
	}
	count = SSL_write(cn->ssl_h, (const void *)message, (int)size);
	ERR_print_errors(errbio);
	if (count <= 0) {
		int err = SSL_get_error(cn->ssl_h, count);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE
				|| err == SSL_ERROR_WANT_CONNECT
				|| err == SSL_ERROR_WANT_ACCEPT)
			return WRITE_KEEP;
		if (cn_is_connected(cn)) {
			mylog(LOG_ERROR, "fd %d: Connection error",
					cn->handle);
			cn->connected = CONN_ERROR;
		}
		return WRITE_ERROR;
	}
	if (count != (int)size) {
		/* abnormal : openssl keeps writing until message is not fully
		 * sent */
		mylog(LOG_ERROR, "SSL_write wrote only %d while message length is %d",
				count,size);
	}

	mylog(LOG_DEBUGVERB, "%d/%d bytes sent", count, size);
	return WRITE_OK;
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define X509_OBJECT_get0_X509(o) ((o)->data.x509)
#define X509_STORE_CTX_get_by_subject(vs, type, name, ret) X509_STORE_get_by_subject(vs, type, name, ret)

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
	// bip doesn't use q parameter
	assert(q == NULL);
	dh->p = p;
	dh->g = g;

	return 1;
}

X509_OBJECT *X509_OBJECT_new()
{
	X509_OBJECT *ret = OPENSSL_malloc(sizeof(*ret));

	if (ret != NULL) {
		memset(ret, 0, sizeof(*ret));
		ret->type = X509_LU_FAIL;
	} else {
		X509err(X509_F_X509_VERIFY_CERT, ERR_R_MALLOC_FAILURE);
	}
	return ret;
}

void X509_OBJECT_free(X509_OBJECT *a)
{
	if (a == NULL)
		return;
	switch (a->type) {
	default:
		break;
	case X509_LU_X509:
		X509_free(a->data.x509);
		break;
	case X509_LU_CRL:
		X509_CRL_free(a->data.crl);
		break;
	}
	OPENSSL_free(a);
}
#endif
#endif

static int _write_socket(connection_t *cn, char *message)
{
	size_t size;
	size_t tcount = 0;
	ssize_t count;

	size = strlen(message);
	if (size == 0)
		return WRITE_OK;
	/* loop if we wrote some data but not everything, or if error is
	 * EINTR */
	do {
		count = write(cn->handle, ((const char *)message) + tcount,
					size - tcount);
		if (count > 0) {
			tcount += (size_t)count;
			if (tcount == size)
				return WRITE_OK;
		}
	} while (count > 0 || (count < 0 && errno == EINTR));

	/* If we reach this point, we have a partial write */
	assert(count != 0);

	/* if no fatal error, return WRITE_KEEP, which makes caller keep line
	 * in its FIFO
	 *
	 * Shitty: we might have written a partial line, so we hack the line...
	 * Callers of _write_socket muse provide a writable message
	 */
// this might be the same
#if EWOULDBLOCK == EAGAIN
	if (errno == EAGAIN || errno == EINPROGRESS) {
#else
	if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINPROGRESS) {
#endif
		memmove(message, message + tcount, size - tcount + 1);
		return WRITE_KEEP;
	}
	/* other errors, EPIPE or worse, close the connection, repport error */
	if (cn_is_connected(cn)) {
		if (errno != EPIPE)
			mylog(LOG_INFO, "Broken socket: %s.", strerror(errno));
		connection_close(cn);
		cn->connected = CONN_ERROR;
	}
	mylog(LOG_DEBUGVERB, "write: %d, %s", cn->handle, strerror(errno));
	return WRITE_ERROR;
}

static int write_socket(connection_t *cn, char *line)
{
#ifdef HAVE_LIBSSL
	if (cn->ssl)
		return _write_socket_SSL(cn, line);
	else
#endif
		return _write_socket(cn, line);

}

/* returns 1 if connection must be notified */
static int real_write_all(connection_t *cn)
{
	int ret;
	char *line;

	if (cn == NULL)
		fatal("real_write_all: wrong arguments");

	if (cn->partial) {
		line = cn->partial;
		cn->partial = NULL;
	} else {
		line = list_remove_first(cn->outgoing);
	}

	do {
		ret = write_socket(cn, line);

		switch (ret) {
		case WRITE_ERROR:
			/* we might as well free(line) here */
			list_add_first(cn->outgoing, line);
			return 1;
		case WRITE_KEEP:
			/* interrupted or not ready */
			assert(cn->partial == NULL);
			cn->partial = line;
			return 0;
		case WRITE_OK:
			free(line);
			break;
		default:
			fatal("internal error 6");
			break;
		}

		if (cn->anti_flood)
			/* one line at a time */
			break;
	} while ((line = list_remove_first(cn->outgoing)));
	return 0;
}

/*
 * May only be used when writing to the client or when sending
 * timing-sensitive data to the server (PONG, PING for lagtest, QUIT)
 * because fakelag is not enforced.
 */
void write_line_fast(connection_t *cn, char *line)
{
	int r;
	char *nline = bip_strdup(line);

	if (cn->partial) {
		list_add_first(cn->outgoing, nline);
	} else {
		r = write_socket(cn, nline);
		switch (r) {
		case WRITE_KEEP:
			cn->partial = nline;
			break;
		case WRITE_ERROR:
		case WRITE_OK:
			free(nline);
			break;
		default:
			fatal("internal error 7");
			break;
		}
	}
}

void write_lines(connection_t *cn, list_t *lines)
{
	list_append(cn->outgoing, lines);
	if (cn_want_write(cn))
		real_write_all(cn);
}

void write_line(connection_t *cn, char *line)
{
	list_add_last(cn->outgoing, bip_strdup(line));
	if (cn_want_write(cn))
		real_write_all(cn);
}

list_t *read_lines(connection_t *cn, int *error)
{
	list_t *ret = NULL;

	switch (cn->connected) {
	case CONN_TIMEOUT:
	case CONN_ERROR:
	case CONN_DISCONN:
	case CONN_EXCEPT:
	case CONN_UNTRUSTED:
		*error = 1;
		ret = NULL;
		break;
	case CONN_NEW:
	case CONN_INPROGRESS:
	case CONN_NEED_SSLIZE:
		*error = 0;
		ret = NULL;
		break;
	case CONN_OK:
		*error = 0;
		ret = cn->incoming_lines;
		cn->incoming_lines = NULL;
		break;
	default:
		fatal("internal error 8");
		break;
	}
	return ret;
}

#ifdef HAVE_LIBSSL
/* returns 1 if connection must be notified */
static int read_socket_SSL(connection_t *cn)
{
	int count;
	size_t max;

	if (cn == NULL)
		return 0;

	if (cn->incoming_end >= CONN_BUFFER_SIZE) {
		mylog(LOG_ERROR, "read_socket_SSL: internal error");
		return -1;
	}

	max = sizeof(char)*(CONN_BUFFER_SIZE - cn->incoming_end);
	if (max > INT_MAX) {
		mylog(LOG_ERROR, "read_socket_SSL: cannot read that much data");
		return -1;
	}

	if (!cn->client && cn->cert == NULL) {
		cn->cert = mySSL_get_cert(cn->ssl_h);
		if (cn->cert == NULL) {
			mylog(LOG_ERROR, "No certificate in SSL read_socket");
			return -1;
		}
	}
	count = SSL_read(cn->ssl_h, (void *)(cn->incoming + cn->incoming_end),
			(int)max);
	ERR_print_errors(errbio);
	if (count < 0) {
		int err = SSL_get_error(cn->ssl_h, count);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE
				|| err == SSL_ERROR_WANT_CONNECT
				|| err == SSL_ERROR_WANT_ACCEPT)
			return 0;
		if (cn_is_connected(cn)) {
			mylog(LOG_ERROR, "fd %d: Connection error",
					cn->handle);
			cn->connected = CONN_ERROR;
		}
		return 1;
	} else if (count == 0) {
/*		int err = SSL_get_error(cn->ssl_h,count);
		if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE
				|| err == SSL_ERROR_WANT_CONNECT
				|| err == SSL_ERROR_WANT_ACCEPT)
			return 0;*/
		if (cn_is_connected(cn)) {
			mylog(LOG_ERROR, "fd %d: Connection lost",
					cn->handle);
			connection_close(cn);
		}
		return 1;
	} else {
		cn->incoming_end += (size_t)count;
		return 0;
	}
}
#endif

/* returns 1 if connection must be notified */
static int read_socket(connection_t *cn)
{
	ssize_t count;
	size_t max;

	if (cn == NULL)
		return 0;

	if (cn->incoming_end >= CONN_BUFFER_SIZE) {
		mylog(LOG_ERROR, "read_socket: internal error");
		return -1;
	}

	max = sizeof(char)*(CONN_BUFFER_SIZE - cn->incoming_end);
	count = read(cn->handle, cn->incoming+cn->incoming_end, max);
	if (count < 0) {
		if (errno == EAGAIN || errno == EINTR || errno == EINPROGRESS)
			return 0;
		if (cn_is_connected(cn)) {
			mylog(LOG_ERROR, "read(fd=%d): Connection error: %s",
					cn->handle, strerror(errno));
			cn->connected = CONN_ERROR;
		}
		return 1;
	} else if (count == 0) {
		if (cn_is_connected(cn)) {
			mylog(LOG_ERROR, "read(fd=%d): Connection lost: %s",
					cn->handle, strerror(errno));
			connection_close(cn);
		}
		return 1;
	} else {
		cn->incoming_end += (unsigned)count;
		return 0;
	}
}

static void data_find_lines(connection_t *cn)
{
	size_t len = 0, lastlen = 0, ssz;
	char *p = cn->incoming;
	char *buf;

	for (;;) {
		while (len < cn->incoming_end && p[len] != '\n')
			len++;
		if (len >= cn->incoming_end || p[len] != '\n')
			break;

		ssz = len - lastlen;
		if (ssz >= 1) {
			if (p[len - 1] == '\r')
				ssz--;
			buf = bip_malloc(ssz + 1);
			memcpy(buf, p + lastlen, ssz);
			buf[ssz] = 0;

			list_add_last(cn->incoming_lines, buf);
		}

		len++;
		lastlen = len;
	}
	if (lastlen) {
		unsigned i;
		for (i = 0; i < cn->incoming_end - lastlen; i++)
			p[i] = p[i + lastlen];
		cn->incoming_end -= lastlen;
	}
}

int cn_is_new(connection_t *cn)
{
	switch (cn->connected) {
	case CONN_TIMEOUT:
	case CONN_ERROR:
	case CONN_DISCONN:
	case CONN_EXCEPT:
	case CONN_NEED_SSLIZE:
	case CONN_OK:
	case CONN_UNTRUSTED:
		return 0;
	case CONN_NEW:
	case CONN_INPROGRESS:
		return 1;
	default:
		fatal("internal error 9");
		return 0;
	}
}

int cn_is_in_error(connection_t *cn)
{
	switch (cn->connected) {
	case CONN_TIMEOUT:
	case CONN_ERROR:
	case CONN_DISCONN:
	case CONN_EXCEPT:
	case CONN_UNTRUSTED:
		return 1;
	case CONN_NEW:
	case CONN_INPROGRESS:
	case CONN_NEED_SSLIZE:
	case CONN_OK:
		return 0;
	default:
		fatal("internal error 10");
		return 1;
	}
}

int cn_is_connected(connection_t *cn)
{
	if (cn == NULL)
		fatal("cn_is_connected, wrong argument");
	return (cn->connected == CONN_OK ? 1 : 0);
}

static int check_event_except(fd_set *fds, connection_t *cn)
{
	if (!cn_is_connected(cn))
		return 0;

	if (cn_is_in_error(cn)) {
		mylog(LOG_ERROR, "Error on fd %d (except, state %d)",
				cn->handle, cn->connected);
		return 1;
	}

	if (!FD_ISSET(cn->handle, fds))
		return 0;

	mylog(LOG_DEBUGTOOMUCH,"fd %d is in exceptions list", cn->handle);
	cn->connected = CONN_EXCEPT;
	return 1;
}

static int check_event_read(fd_set *fds, connection_t *cn)
{
	int ret;

	if (cn_is_in_error(cn)) {
		mylog(LOG_ERROR, "Error on fd %d (read, state %d)",
				cn->handle, cn->connected);
		return 1;
	}

	if (!FD_ISSET(cn->handle, fds))
		return 0;

	mylog(LOG_DEBUGTOOMUCH, "Read positive on fd %d (state %d)", cn->handle,
			cn->connected);

	/* notify caller to make it check for a new client */
	if (cn->listening)
		return 1;

#ifdef HAVE_LIBSSL
	if (cn->ssl)
		ret = read_socket_SSL(cn);
	else
#endif
		ret = read_socket(cn);

	if (ret) {
		mylog(LOG_ERROR, "Error while reading on fd %d",
				cn->handle);
		return 1;
	}

	if (!cn->incoming_lines)
		cn->incoming_lines = list_new(NULL);
	data_find_lines(cn);
	if (list_is_empty(cn->incoming_lines))
		return 0;

	mylog(LOG_DEBUGTOOMUCH, "newlines on fd %d (state %d)", cn->handle,
			cn->connected);
	return 1;
}

static void connection_connected(connection_t *c)
{
	if (c->localip)
		free(c->localip);
	c->localip = connection_localip(c);
	c->localport = connection_localport(c);
	if (c->remoteip)
		free(c->remoteip);
	c->remoteip = connection_remoteip(c);
	c->remoteport = connection_remoteport(c);
}

static int check_event_write(fd_set *fds, connection_t *cn, int *nc)
{
	if (cn_is_in_error(cn)) {
		mylog(LOG_ERROR, "Error on fd %d (write, state %d)",
				cn->handle, cn->connected);
		return 1;
	}

	if (!FD_ISSET(cn->handle, fds)) {
		if (cn_is_connected(cn))
			return 0;

		mylog(LOG_DEBUG, "New socket still not connected (%d)",
				cn->handle);
		/* check timeout (handles connect_trynext) */
		return connection_timedout(cn);
	}

	mylog(LOG_DEBUGTOOMUCH, "Write positive on fd %d (state %d)",
			cn->handle, cn->connected);

	if (cn_is_new(cn)) {
		int err, err2;
		socklen_t errSize = sizeof(err);

		err2 = getsockopt(cn->handle, SOL_SOCKET, SO_ERROR,
				(void *)&err, &errSize);

		if (err2 < 0) {
			mylog(LOG_ERROR, "fd:%d getsockopt error: %s",
					cn->handle, strerror(errno));
			if (cn->connecting_data) {
				close(cn->handle);
				cn->handle = -1;
				connect_trynext(cn);
			}
			return (cn_is_new(cn) || cn->connected ==
					CONN_NEED_SSLIZE) ? 0 : 1;

		} else if (err == EINPROGRESS || err == EALREADY) {
			mylog(LOG_DEBUG, "fd:%d Connection in progress...",
					cn->handle);
			return connection_timedout(cn);
		} else if (err == EISCONN || err == 0) {
#ifdef HAVE_LIBSSL
			if (cn->ssl) {
				cn->connected = CONN_NEED_SSLIZE;
				return 0;
			}
#endif
			cn->connected = CONN_OK;
			connection_connected(cn);
			*nc = 1;
			mylog(LOG_DEBUG, "fd:%d Connection established !",
					cn->handle);
			return 1;
		} else {
			mylog(LOG_WARN, "fd:%d Socket error: %s", cn->handle,
					strerror(err));
			if (cn->connecting_data) {
				close(cn->handle);
				cn->handle = -1;
				connect_trynext(cn);
			}
			return (cn_is_new(cn) || cn->connected ==
					CONN_NEED_SSLIZE) ? 0 : 1;
		}
	}

#ifdef HAVE_LIBSSL
	if (cn->connected == CONN_NEED_SSLIZE) {
		if (SSLize(cn, nc))
			return connection_timedout(cn);
		return 0;
	}
#endif

	if (cn_is_connected(cn) && !list_is_empty(cn->outgoing))
		real_write_all(cn);

	return 0;
}

/* starts empty */
/* capacity: 4 token */
#define TOKEN_MAX 4
/* token generation interval: 1200ms */
#define TOKEN_INTERVAL 1200

static int cn_want_write(connection_t *cn)
{
	if (cn->anti_flood) {
		struct timespec tv;
		unsigned long now;

		/* fill the bucket */
		/* we do not control when we are called */
		/* now is the number of milliseconds since the Epoch,
		 * cn->lasttoken is the number of milliseconds when we
		 * last added a token to the bucket */
		if (!clock_gettime(CLOCK_MONOTONIC, &tv)) {
			if (tv.tv_sec < 0 || tv.tv_nsec < 0)
				fatal("clock_gettime returned negative time");
			now = (unsigned long)(tv.tv_sec * 1000 + tv.tv_nsec / 1000000);
			/* round now to TOKEN_INTERVAL multiple */
			now -= now % TOKEN_INTERVAL;
			if (now < cn->lasttoken) {
				/* time shift or integer overflow */
				cn->token = 1;
				cn->lasttoken = now;
			} else if (now > cn->lasttoken + TOKEN_INTERVAL) {
				cn->token += (unsigned)((now - cn->lasttoken) /
					TOKEN_INTERVAL);
				if (cn->token > TOKEN_MAX)
					cn->token = TOKEN_MAX;
				if (!cn->token)
					cn->token = 1;
				cn->lasttoken = now;
			}
		} else
			/* if clock_gettime() fails, juste ignore
			 * antiflood */
			cn->token = 1;

		/* use a token if needed and available */
		if (!list_is_empty(cn->outgoing) && cn->token > 0) {
			cn->token--;
			return 1;
		}
		return 0;
	}
	return !list_is_empty(cn->outgoing);
}


list_t *wait_event(list_t *cn_list, time_t *msec, int *nc)
{
	fd_set fds_read, fds_write, fds_except;
	int maxfd = -1, err, errtime;
	list_t *cn_newdata;
	list_iterator_t it;
	struct timeval tv;
	struct timespec btv, etv;
	*nc = 0;

	cn_newdata = list_new(list_ptr_cmp);
	FD_ZERO(&fds_read);
	FD_ZERO(&fds_write);
	FD_ZERO(&fds_except);
	for (list_it_init(cn_list, &it); list_it_item(&it); list_it_next(&it)) {
		connection_t *cn = list_it_item(&it);
		if (cn == NULL)
			fatal("wait_event: wrong argument");

		mylog(LOG_DEBUGTOOMUCH, "I've seen socket %d !", cn->handle);
		if (cn->connected == CONN_DISCONN) {
			list_add_first_uniq(cn_newdata, cn);
			continue;
		}

		/*
		 * This shouldn't happen ! just in case...
		 */
		if (cn->handle < 0 || cn->handle >= FD_SETSIZE)
			fatal("wait_event invalid socket %d", cn->handle);

		/* exceptions are OOB and disconnections */
		FD_SET(cn->handle, &fds_except);
		maxfd = (cn->handle > maxfd ? cn->handle : maxfd);

		/*
		 * if connected, we're looking for new incoming data
		 * if new or lines waiting to be sent, we want
		 * to know if it's ready or not.
		 */
		if (cn_is_connected(cn)) {
			FD_SET(cn->handle, &fds_read);
			mylog(LOG_DEBUGTOOMUCH, "Test read on fd %d %d:%d",
					cn->handle, cn->connected,
					cn_is_connected(cn));
		}

		/* we NEVER want to check write on a listening socket */
		if (cn->listening)
			continue;

		if (!cn_is_connected(cn) || cn_want_write(cn)) {
			FD_SET(cn->handle, &fds_write);
			mylog(LOG_DEBUGTOOMUCH, "Test write on fd %d %d:%d",
					cn->handle, cn->connected,
					cn_is_connected(cn));
		}
	}

	/* if no connection is active, return the list... empty... */
	if (maxfd == -1) {
		struct timespec req, rem;
		req.tv_sec = *msec * 1000;
		req.tv_nsec = 0;
		nanosleep(&req, &rem);
		*msec = rem.tv_sec;
		return cn_newdata;
	}

	tv.tv_sec = *msec / 1000;
	tv.tv_usec = (*msec % 1000) * 1000;
	mylog(LOG_DEBUGTOOMUCH, "msec: %d, sec: %d, usec: %d", *msec, tv.tv_sec,
			tv.tv_usec);

	errtime = clock_gettime(CLOCK_MONOTONIC, &btv);
	if (errtime != 0) {
		fatal("clock_gettime: %s", strerror(errno));
	}

	err = select(maxfd + 1, &fds_read, &fds_write, &fds_except, &tv);

	if (err == 0) {
		/* select timed-out */
		mylog(LOG_DEBUGTOOMUCH, "Select timed-out. irc.o timer !");
		*msec = 0;
		return cn_newdata;
	} else {
		mylog(LOG_DEBUGTOOMUCH, "msec: %d, sec: %d, usec: %d", *msec,
				tv.tv_sec, tv.tv_usec);
	}

	errtime = clock_gettime(CLOCK_MONOTONIC, &etv);
	if (errtime != 0) {
		fatal("clock_gettime: %s", strerror(errno));
	}

	if (etv.tv_sec < btv.tv_sec)
		mylog(LOG_ERROR, "Time rewinded ! not touching interval");
	else {
		*msec -= (etv.tv_sec - btv.tv_sec) * 1000
			+ (etv.tv_nsec - btv.tv_nsec) / 1000000;
		/* in case we go forward in time */
		if (*msec < 0)
			*msec = 0;
	}

	if (err < 0) {
		if (errno == EINTR)
			return cn_newdata;
		fatal("select(): %s", strerror(errno));
	}

	for (list_it_init(cn_list, &it); list_it_item(&it); list_it_next(&it)) {
		connection_t *cn = list_it_item(&it);
		int toadd = 0;

		if (check_event_except(&fds_except, cn)) {
			mylog(LOG_DEBUGTOOMUCH, "Notify on FD %d (state %d)",
					cn->handle, cn->connected);
			list_add_first_uniq(cn_newdata, cn);
			continue;
		}
		if (check_event_write(&fds_write, cn, nc)) {
			if (cn_is_in_error(cn))
				toadd = 1;
		}

		if (check_event_read(&fds_read, cn)) {
			mylog(LOG_DEBUGTOOMUCH, "Notify on FD %d (state %d)",
					cn->handle, cn->connected);
			toadd = 1;
		}
		if (toadd)
			list_add_first_uniq(cn_newdata, cn);
	}
	return cn_newdata;
}

static void create_socket(char *dsthostname, char *dstport, char *srchostname,
		char *srcport, connection_t *cn)
{
	int err;
	struct connecting_data *cdata;
	struct addrinfo hint;

	memset(&hint, 0, sizeof(hint));
	hint.ai_flags = AI_PASSIVE;
	hint.ai_family = PF_UNSPEC;
	hint.ai_socktype = SOCK_STREAM;
	hint.ai_protocol = 0;

	cn->connected = CONN_ERROR;
	cdata = (struct connecting_data *)
		bip_malloc(sizeof(struct connecting_data));
	cdata->dst = cdata->src = cdata->cur = NULL;

	err = getaddrinfo(dsthostname, dstport, &hint, &cdata->dst);
	if (err) {
		mylog(LOG_ERROR, "getaddrinfo(%s): %s", dsthostname,
				gai_strerror(err));
		connecting_data_free(cdata);
		cdata = NULL;
		return;
	}

	if (srchostname || srcport) {
		if ((err = getaddrinfo(srchostname, srcport, &hint,
						&cdata->src))) {
			/* not fatal ? maybe a config option is needed */
			mylog(LOG_ERROR, "getaddrinfo(src): %s",
					gai_strerror(err));
			cdata->src = NULL;
		}
	}

	cdata->cur = cdata->dst;
	cn->connecting_data = cdata;

	connect_trynext(cn);
}


static void create_listening_socket(char *hostname, char *port,
		connection_t *cn)
{
	int multi_client = 1;
	int err;
	struct addrinfo *res, *cur;
	struct addrinfo hint = {
		.ai_flags = AI_PASSIVE,
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = 0,

		.ai_addrlen = 0,
		.ai_addr = 0,
		.ai_canonname = 0,
		.ai_next = 0
	};

	cn->connected = CONN_ERROR;

	err = getaddrinfo(hostname, port, &hint, &res);
	if (err) {
		mylog(LOG_ERROR, "getaddrinfo(): %s", gai_strerror(err));
		return;
	}

	for (cur = res ; cur ; cur = cur->ai_next) {
		if ((cn->handle = socket(cur->ai_family, cur->ai_socktype,
						cur->ai_protocol)) < 0) {
			mylog(LOG_WARN, "socket : %s", strerror(errno));
			continue;
		}

		if (cn->handle >= FD_SETSIZE) {
			mylog(LOG_WARN, "too many fd used, close listening socket %d",
					cn->handle);

			if (close(cn->handle) == -1)
				mylog(LOG_WARN, "Error on socket close: %s",
						strerror(errno));

			cn->handle = -1;
			break;
		}

		if (setsockopt(cn->handle, SOL_SOCKET, SO_REUSEADDR,
					(char *)&multi_client,
					(socklen_t)sizeof(multi_client)) < 0) {
			mylog(LOG_WARN, "setsockopt() : %s", strerror(errno));
			close(cn->handle);
			cn->handle = -1;
			continue;
		}

		socket_set_nonblock(cn->handle);

		if (bind(cn->handle, cur->ai_addr, cur->ai_addrlen) < 0) {
			mylog(LOG_WARN, "bind() : %s", strerror(errno));
			close(cn->handle);
			cn->handle = -1;
			continue;
		}

		err = listen(cn->handle, 256);
		if (err == -1) {
			mylog(LOG_WARN, "listen() : %s", strerror(errno));
			close(cn->handle);
			cn->handle = -1;
			continue;
		}

		freeaddrinfo(res);
		cn->connected = CONN_OK;
		return;
	}
	freeaddrinfo(res);
	mylog(LOG_ERROR, "Unable to bind/listen");
	cn->connected = CONN_ERROR;
}

static connection_t *connection_init(int anti_flood, int ssl, time_t timeout,
		int listen)
{
	connection_t *conn;
	char *incoming;
	list_t *outgoing;

	conn = (connection_t *)bip_calloc(sizeof(connection_t), (size_t)1);
	incoming = (char *)bip_malloc((size_t)CONN_BUFFER_SIZE);
	outgoing = list_new(NULL);

	conn->anti_flood = anti_flood;
	conn->ssl = ssl;
	conn->lasttoken = 0;
	conn->token = TOKEN_MAX;
	conn->timeout = (listen ? 0 : timeout);
	conn->connect_time = 0;
	conn->incoming = incoming;
	conn->incoming_end = 0;
	conn->outgoing = outgoing;
	conn->incoming_lines = NULL;
	conn->user_data = NULL;
	conn->listening = listen;
	conn->handle = -1;
	conn->client = 0;
	conn->connecting_data = NULL;
#ifdef HAVE_LIBSSL
	conn->ssl_ctx_h = NULL;
	conn->ssl_h = NULL;
	conn->cert = NULL;
	conn->ssl_check_mode = SSL_CHECK_NONE;
#endif
	conn->connected = CONN_NEW;
	return conn;
}

#ifdef HAVE_LIBSSL
static int ctx_set_dh(SSL_CTX *ctx)
{
	/* Return ephemeral DH parameters. */
	DH *dh = NULL;
	FILE *f;
	long ret;

	if ((f = fopen(conf_client_dh_file, "r")) == NULL) {
		mylog(LOG_ERROR, "Unable to open DH parameters (%s): %s",
				conf_client_dh_file, strerror(errno));
		return 0;
	}

	dh = PEM_read_DHparams(f, NULL, NULL, NULL);
	fclose(f);

	if (dh == NULL) {
		mylog(LOG_ERROR, "Could not parse DH parameters from: %s",
				conf_client_dh_file);
		return 0;
	}

	ret = SSL_CTX_set_tmp_dh(ctx, dh);
	DH_free(dh);

	if (ret != 1) {
		mylog(LOG_ERROR, "Unable to set DH parameters: %s",
				ERR_error_string(ERR_get_error(), NULL));
		return 0;
	}

	return 1;
}
#endif

connection_t *accept_new(connection_t *cn)
{
	connection_t *conn;
	int err;
	socklen_t sa_len = sizeof (struct sockaddr);
	struct sockaddr sa;

	mylog(LOG_DEBUG, "Trying to accept new client on %d", cn->handle);
	err = accept(cn->handle, &sa, &sa_len);

	if (err < 0) {
		fatal("accept failed: %s", strerror(errno));
	}

	if (err >= FD_SETSIZE) {
		mylog(LOG_WARN, "too many client connected, close %d", err);

		if (close(err) == -1)
			mylog(LOG_WARN, "Error on socket close: %s",
					strerror(errno));

		return NULL;
	}

	socket_set_nonblock(err);

	conn = connection_init(cn->anti_flood, cn->ssl, cn->timeout, 0);
	conn->connect_time = time(NULL);
	conn->user_data = cn->user_data;
	conn->handle = err;
	conn->client = 1;
#ifdef HAVE_LIBSSL
	if (cn->ssl) {
		if (!sslctx) {
			mylog(LOG_DEBUG, "No SSL context available for "
					"accepted connections. "
					"Initializing...");
			if (!(sslctx = SSL_init_context(conf_client_ciphers))) {
				mylog(LOG_ERROR, "SSL context initialization "
						"failed");
				connection_free(conn);
				return NULL;
			}

			if (!conf_client_dh_file) {
				// try with a default path but don't fail if it doesn't exist
				conf_client_dh_file = default_path(conf_biphome, "dh.pem",
						"DH parameters");

				struct stat st_buf;
				if (stat(conf_client_dh_file, &st_buf) != 0) {
					free(conf_client_dh_file);
					conf_client_dh_file = NULL;
				}
			}

			if (conf_client_dh_file) {
				if (!ctx_set_dh(sslctx)) {
					mylog(LOG_ERROR, "SSL Unable to load DH "
							"parameters");
					connection_free(conn);
					return NULL;
				}
			}

			if (!SSL_CTX_use_certificate_chain_file(sslctx,
						conf_ssl_certfile))
				mylog(LOG_WARN, "SSL: Unable to load "
						"certificate file");
			if (!SSL_CTX_use_PrivateKey_file(sslctx,
						conf_ssl_certfile,
						SSL_FILETYPE_PEM))
				mylog(LOG_WARN, "SSL: Unable to load key file");
		}

		conn->ssl_h = SSL_new(sslctx);
		if (!conn->ssl_h) {
			connection_free(conn);
			SSL_CTX_free(sslctx);
			return NULL;
		}
		SSL_set_accept_state(conn->ssl_h);
	}
#endif
	mylog(LOG_DEBUG, "New client on socket %d !",conn->handle);

	return conn;
}

connection_t *listen_new(char *hostname, int port, int ssl)
{
	connection_t *conn;
	char portbuf[20];
	/* TODO: allow litteral service name in the function interface */
	if (snprintf(portbuf, (size_t)20, "%d", port) >= 20)
		portbuf[19] = '\0';

	/*
	 * SSL flag is only here to tell program to convert socket to SSL after
	 * accept(). Listening socket will NOT be SSL
	 */
	conn = connection_init(0, ssl, (time_t)0, 1);
	create_listening_socket(hostname, portbuf, conn);

	return conn;
}

static connection_t *_connection_new(char *dsthostname, char *dstport,
		char *srchostname, char *srcport, time_t timeout)
{
	connection_t *conn;

	conn = connection_init(1, 0, timeout, 0);
	create_socket(dsthostname, dstport, srchostname, srcport, conn);

	return conn;
}

#ifdef HAVE_LIBSSL
static SSL_CTX *SSL_init_context(char *ciphers)
{
	int fd, flags, rng;
	ssize_t ret;
	char buf[1025];
	SSL_CTX *ctx;

	if (!ssl_initialized) {
		SSL_library_init();
		SSL_load_error_strings();
		errbio = BIO_new_fp(conf_global_log_file, BIO_NOCLOSE);

		ssl_cx_idx = SSL_get_ex_new_index((size_t)0, "bip connection_t",
			NULL, NULL,NULL);

		flags = O_RDONLY;
		flags |= O_NONBLOCK;
		fd = open("/dev/random", flags);
		if (fd < 0) {
			mylog(LOG_WARN, "SSL: /dev/random not ready, unable "
					"to manually seed PRNG.");
			goto prng_end;
		}

		do {
			ret = read(fd, buf, (size_t)1024);
			if (ret <= 0) {
				mylog(LOG_ERROR,"/dev/random: %s",
						strerror(errno));
				goto prng_end;
			}
			mylog(LOG_DEBUG, "PRNG seeded with %d /dev/random "
					"bytes", ret);
			RAND_seed(buf, (int)ret);
		} while (!(rng = RAND_status()));

prng_end:
		do {
			ret = close(fd);
		} while (ret != 0 && errno == EINTR);
		if (RAND_status()) {
			mylog(LOG_DEBUG, "SSL: PRNG is seeded !");
		} else {
			mylog(LOG_WARN, "SSL: PRNG is not seeded enough");
			mylog(LOG_WARN, "     OpenSSL will use /dev/urandom if "
					 "available.");
		}

		ssl_initialized = 1;
	}

	/* allocated by function */
	if (!(ctx = SSL_CTX_new(SSLv23_method()))) {
		ERR_print_errors(errbio);
		return NULL;
	}
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_BOTH);
	SSL_CTX_set_timeout(ctx, (long)60);
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
	if (ciphers && !SSL_CTX_set_cipher_list(ctx, ciphers)) {
		SSL_CTX_free(ctx);
		return NULL;
	}

	return ctx;
}

static int bip_ssl_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	char subject[256];
	char issuer[256];
	X509 *err_cert;
	int err, depth;
	SSL *ssl;
	connection_t *c;
	X509_OBJECT *xobj;
	int result;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	/* Retrieve the SSL and connection_t objects from the store */
	ssl = X509_STORE_CTX_get_ex_data(ctx,
			SSL_get_ex_data_X509_STORE_CTX_idx());
	c = SSL_get_ex_data(ssl, ssl_cx_idx);

	mylog(LOG_INFO, "SSL cert check: now at depth=%d", depth);
	X509_NAME_oneline(X509_get_subject_name(err_cert), subject, 256);
	X509_NAME_oneline(X509_get_issuer_name(err_cert), issuer, 256);
	mylog(LOG_INFO, "Subject: %s", subject);
	mylog(LOG_INFO, "Issuer: %s", issuer);

	result = preverify_ok;

	/* in basic mode (mode 1), accept a leaf certificate if we can find it
	 * in the store */
	if (c->ssl_check_mode == SSL_CHECK_BASIC && result == 0 &&
			(err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY ||
			 err == X509_V_ERR_CERT_UNTRUSTED ||
			 err == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE ||
			 err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ||
			 err == X509_V_ERR_CERT_HAS_EXPIRED ||
			 err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)) {

		if (!(xobj = X509_OBJECT_new())) {
			result = 0;
		} else {
			if (X509_STORE_CTX_get_by_subject(ctx, X509_LU_X509,
					X509_get_subject_name(err_cert), xobj) > 0 &&
					!X509_cmp(X509_OBJECT_get0_X509(xobj), err_cert)) {
				if (err == X509_V_ERR_CERT_HAS_EXPIRED)
					mylog(LOG_INFO, "Basic mode; Accepting "
							"*expired* peer certificate "
							"found in store.");
				else
					mylog(LOG_INFO, "Basic mode; Accepting peer "
						"certificate found in store.");

				result = 1;
				err = X509_V_OK;
				X509_STORE_CTX_set_error(ctx, err);
			} else {
				mylog(LOG_INFO, "Basic mode; peer certificate NOT "
						"in store, rejecting it!");
				err = X509_V_ERR_CERT_REJECTED;
				X509_STORE_CTX_set_error(ctx, err);

				link_add_untrusted(c->user_data, X509_dup(err_cert));
			}
			X509_OBJECT_free(xobj);
		}
	}

	if (!result) {
		/* We have a verify error! Log it */
		mylog(LOG_ERROR, "SSL cert check failed at depth=%d: %s (%d)",
				depth, X509_verify_cert_error_string((long)err), err);
	}

	return result;
}

static int SSLize(connection_t *cn, int *nc)
{
	int err, err2;
	long errl;

	if (cn == NULL)
		return 1;

	if (cn->listening) {
		mylog(LOG_ERROR, "Can't use SSL with listening socket.");
		return 0;
	}

	if (!SSL_set_fd(cn->ssl_h, cn->handle)) {
		mylog(LOG_ERROR, "unable to associate FD to SSL structure");
		cn->connected = CONN_ERROR;
		return 1;
	}

	if (cn->client)
		err = SSL_accept(cn->ssl_h);
	else
		err = SSL_connect(cn->ssl_h);

	err2 = SSL_get_error(cn->ssl_h, err);
	ERR_print_errors(errbio);

	if (err2 == SSL_ERROR_NONE) {
		const SSL_CIPHER *cipher;
		char buf[128];
		size_t len;

		cipher = SSL_get_current_cipher(cn->ssl_h);
		SSL_CIPHER_description(cipher, buf, 128);
		len = strlen(buf);
		if (len > 0)
			buf[len - 1] = '\0';
		mylog(LOG_DEBUG, "Negotiated ciphers: %s", buf);

		cn->connected = CONN_OK;
		connection_connected(cn);
		*nc = 1;
		return 0;
	}

	switch (cn->ssl_check_mode) {
	case SSL_CHECK_NONE:
		break;
	case SSL_CHECK_BASIC:
		if((errl = SSL_get_verify_result(cn->ssl_h)) != X509_V_OK) {
			mylog(LOG_ERROR, "Certificate check failed: %s (%ld)!",
				X509_verify_cert_error_string(errl), errl);
			cn->connected = CONN_UNTRUSTED;
			return 1;
		}
		break;
	case SSL_CHECK_CA:
		if((errl = SSL_get_verify_result(cn->ssl_h)) != X509_V_OK) {
			mylog(LOG_ERROR, "Certificate check failed: %s (%ld)!",
				X509_verify_cert_error_string(errl), errl);
			cn->connected = CONN_UNTRUSTED;
			return 1;
		}
		break;
	default:
		mylog(LOG_ERROR, "Unknown ssl_check_mode (%d)!", cn->ssl_check_mode);
		return 1;
	}

	if (err2 == SSL_ERROR_SYSCALL) {
		mylog(LOG_ERROR, "Error with socket during ssl handshake.");
		connection_close(cn);
		cn->connected = CONN_ERROR;
		return 1;
	}
	/* From now on, we are on error, thus we return 1 to check timeout */
	if (err2 == SSL_ERROR_ZERO_RETURN || err2 == SSL_ERROR_SSL) {
		mylog(LOG_ERROR, "Error in SSL handshake.");
		connection_close(cn);
		cn->connected = CONN_ERROR;
		return 1;
	}
	/* Here are unhandled errors/resource waiting. Timeout must be
	 * checked but connection may still be valid */
	return 1;
}

static connection_t *_connection_new_SSL(char *dsthostname, char *dstport,
		char *srchostname, char *srcport, char *ciphers, int check_mode,
		char *check_store, char *ssl_client_certfile, time_t timeout)
{
	connection_t *conn;

	conn = connection_init(1, 1, timeout, 0);
	if (!(conn->ssl_ctx_h = SSL_init_context(ciphers))) {
		mylog(LOG_ERROR, "SSL context initialization failed");
		return conn;
	}

	conn->cert = NULL;
	conn->ssl_check_mode = check_mode;

	switch (conn->ssl_check_mode) {
	struct stat st_buf;
	case SSL_CHECK_NONE:
		break;
	case SSL_CHECK_BASIC:
		if (!SSL_CTX_load_verify_locations(conn->ssl_ctx_h, check_store,
				NULL)) {
			mylog(LOG_ERROR, "Can't assign check store to "
					"SSL connection! Proceeding without!");
		}
		break;
	case SSL_CHECK_CA:
		if (!check_store) {
			if (SSL_CTX_set_default_verify_paths(conn->ssl_ctx_h)) {
				mylog(LOG_INFO, "No SSL certificate check store configured. "
						"Default store will be used.");
				break;
			} else {
				mylog(LOG_ERROR, "No SSL certificate check store configured "
						"and cannot use default store!");
				return conn;
			}
		}
		// Check if check_store is a file or directory
		if (stat(check_store, &st_buf) == 0) {
			if (st_buf.st_mode & S_IFDIR) {
				if (!SSL_CTX_load_verify_locations(conn->ssl_ctx_h, NULL,
						check_store)) {
					mylog(LOG_ERROR, "Can't assign check store to "
							"SSL connection!");
					return conn;
				}
				break;
			}
			if (st_buf.st_mode & S_IFREG) {
				if (!SSL_CTX_load_verify_locations(conn->ssl_ctx_h, check_store,
						NULL)) {
					mylog(LOG_ERROR, "Can't assign check store to "
							"SSL connection!");
					return conn;
				}
				break;
			}
			mylog(LOG_ERROR, "Specified SSL certificate check store is neither "
					"a file nor a directory.");
			return conn;
		}
		mylog(LOG_ERROR, "Can't open SSL certificate check store! Check path "
				"and permissions.");
		return conn;
	default:
		fatal("Unknown SSL cert check mode.");
	}

	switch (conn->ssl_check_mode) {
	case SSL_CHECK_NONE:
		SSL_CTX_set_verify(conn->ssl_ctx_h, SSL_VERIFY_NONE, NULL);
		break;
	case SSL_CHECK_BASIC:
		SSL_CTX_set_verify(conn->ssl_ctx_h, SSL_VERIFY_PEER,
				bip_ssl_verify_callback);
		/* SSL_CTX_set_verify_depth(conn->ssl_ctx_h, 0); */
		break;
	case SSL_CHECK_CA:
		SSL_CTX_set_verify(conn->ssl_ctx_h, SSL_VERIFY_PEER,
				bip_ssl_verify_callback);
		break;
	default:
		fatal("Unknown SSL cert check mode.");
	}

	if (ssl_client_certfile) {
		if (!SSL_CTX_use_certificate_chain_file(conn->ssl_ctx_h,
					ssl_client_certfile))
			mylog(LOG_WARN, "SSL: Unable to load certificate file");
		else if (!SSL_CTX_use_PrivateKey_file(conn->ssl_ctx_h,
					ssl_client_certfile, SSL_FILETYPE_PEM))
			mylog(LOG_WARN, "SSL: Unable to load key file");
		else
			mylog(LOG_INFO, "SSL: using %s pem file as client SSL "
					"certificate", ssl_client_certfile);
	}

	conn->ssl_h = SSL_new(conn->ssl_ctx_h);
	if (conn->ssl_h == NULL) {
		mylog(LOG_ERROR, "Unable to allocate SSL structures");
		return conn;
	}
	/* ys: useless as long as we have a context by connection
	if (sslctx->session_cache_head)
		if (!SSL_set_session(conn->ssl_h, sslctx->session_cache_head))
			mylog(LOG_ERROR, "unable to set SSL session id to"
					" most recent used");
	*/
	SSL_set_connect_state(conn->ssl_h);

	/* Put our connection_t in the SSL object for the verify callback */
	SSL_set_ex_data(conn->ssl_h, ssl_cx_idx, conn);

	create_socket(dsthostname, dstport, srchostname, srcport, conn);

	return conn;
}
#endif

connection_t *connection_new(char *dsthostname, int dstport, char *srchostname,
		int srcport, int ssl, char *ssl_ciphers, int ssl_check_mode,
		char *ssl_check_store, char *ssl_client_certfile, time_t timeout)
{
	char dstportbuf[20], srcportbuf[20], *tmp;
#ifndef HAVE_LIBSSL
	(void)ssl;
	(void)ssl_ciphers;
	(void)ssl_check_mode;
	(void)ssl_check_store;
	(void)ssl_client_certfile;
#endif
	/* TODO: allow litteral service name in the function interface */
	if (snprintf(dstportbuf, (size_t)20, "%d", dstport) >= 20)
		dstportbuf[19] = '\0';
	if (srcport) {
		if (snprintf(srcportbuf, (size_t)20, "%d", srcport) >= 20)
			srcportbuf[19] = '\0';
		tmp = srcportbuf;
	} else
		tmp = NULL;
#ifdef HAVE_LIBSSL
	if (ssl)
		return _connection_new_SSL(dsthostname, dstportbuf, srchostname,
				tmp, ssl_ciphers, ssl_check_mode, ssl_check_store,
				ssl_client_certfile, timeout);
	else
#endif
		return _connection_new(dsthostname, dstportbuf, srchostname,
				tmp, timeout);
}

int cn_is_listening(connection_t *cn)
{
	if (cn == NULL)
		return 0;
	else
		return cn->listening;
}

/* returns 1 if connection must be notified */
static int connection_timedout(connection_t *cn)
{
	if (cn_is_connected(cn) || !cn->timeout)
		return 0;

	if (!cn->connecting_data)
		fatal("connection_timedout called with no connecting_data!\n");

	if (time(NULL) - cn->connect_time > cn->timeout) {
		/* connect() completion timed out */
		close(cn->handle);
		cn->handle = -1;
		connect_trynext(cn);
		if (!cn_is_new(cn) && cn->connected != CONN_NEED_SSLIZE)
			return 1;
	}
	return 0;
}

static int socket_set_nonblock(int s)
{
	int flags;

	if ((flags = fcntl(s, F_GETFL, 0)) < 0) {
		mylog(LOG_ERROR, "Cannot set socket %d to non blocking : %s",
				s, strerror(errno));
		return 0;
	}

	if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
		mylog(LOG_ERROR, "Cannot set socket %d to non blocking : %s",
				s, strerror(errno));
		return 0;
	}
	return 1;
}

#ifdef TEST
int main(int argc,char* argv[])
{
	connection_t *conn, *conn2;
	int s, cont = 1;

	if (argc != 3) {
		fprintf(stderr,"Usage: %s host port\n",argv[0]);
		exit(1);
	}
	conn = connection_init(0, 0, (time_t)0, 1);
	conn->connect_time = time(NULL);
	create_listening_socket(argv[1],argv[2],&conn);
	if (s == -1) {
		mylog(LOG_ERROR, "socket() : %s", strerror(errno));
		exit(1);
	}
	mylog(LOG_DEBUG, "Socket number %d",s);

	while (cont) {
		conn2 = accept_new(conn);
		if (conn2) {
			mylog(LOG_DEBUG, "New client");
			cont = 0;
		}
		sleep(1);
	}
	while (1) {
		int ret = read_socket(conn2);
		mylog(LOG_DEBUGTOOMUCH, "READ: %d %*s",ret, conn2->incoming,
				conn2->incoming_end);
		conn2->incoming_end = 0;
		sleep(1);
	}
	return 0;
}
#endif

uint16_t connection_localport(connection_t *cn)
{
	struct sockaddr_in addr;
	int err;
	socklen_t addrlen;

	if (cn->handle <= 0)
		return 0;

	addrlen = sizeof(addr);
	err = getsockname(cn->handle, (struct sockaddr *)&addr, &addrlen);
	if (err != 0) {
		mylog(LOG_ERROR, "in getsockname(%d): %s", cn->handle,
				strerror(errno));
		return 0;
	}

	return ntohs(addr.sin_port);
}

uint16_t connection_remoteport(connection_t *cn)
{
	struct sockaddr_in addr;
	int err;
	socklen_t addrlen;

	if (cn->handle <= 0)
		return 0;

	addrlen = sizeof(addr);
	err = getpeername(cn->handle, (struct sockaddr *)&addr, &addrlen);
	if (err != 0) {
		mylog(LOG_ERROR, "in getpeername(%d): %s", cn->handle,
				strerror(errno));
		return 0;
	}

	return ntohs(addr.sin_port);
}

static char *socket_ip(int fd, int remote)
{
	struct sockaddr addr;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	socklen_t addrlen;
	socklen_t addrlen4;
	socklen_t addrlen6;
	int err;
	char *ip;
	const char *ret;

	if (fd <= 0)
		return NULL;

	addrlen = sizeof(addr);

	/* getsockname every time to get IP version */
	err = getsockname(fd, (struct sockaddr *)&addr, &addrlen);
	if (err != 0) {
		mylog(LOG_ERROR, "in getsockname(%d): %s", fd,
				strerror(errno));
		return NULL;
	}

	ip = bip_malloc((size_t)65);

	switch (addr.sa_family) {
	case AF_INET:
		addrlen4 = sizeof(addr4);

		if (remote) {
			err = getpeername(fd, (struct sockaddr *)&addr4,
					&addrlen4);
			if (err != 0) {
				mylog(LOG_ERROR, "in getpeername(%d): %s", fd,
						strerror(errno));
				free(ip);
				return NULL;
			}
		} else {
			err = getsockname(fd, (struct sockaddr *)&addr4,
					&addrlen4);
			if (err != 0) {
				mylog(LOG_ERROR, "in getsockname(%d): %s", fd,
						strerror(errno));
				free(ip);
				return NULL;
			}
		}
		ret = inet_ntop(AF_INET, &(addr4.sin_addr.s_addr), ip, 64);
		if (ret == NULL) {
			mylog(LOG_ERROR, "in inet_ntop: %s", strerror(errno));
			free(ip);
			return NULL;
		}
		break;
	case AF_INET6:
		addrlen6 = sizeof(addr6);

		if (remote) {
			err = getpeername(fd, (struct sockaddr *)&addr6,
					&addrlen6);
			if (err != 0) {
				mylog(LOG_ERROR, "in getpeername(%d): %s", fd,
						strerror(errno));
				free(ip);
				return NULL;
			}
		} else {
			err = getsockname(fd, (struct sockaddr *)&addr6,
					&addrlen6);
			if (err != 0) {
				mylog(LOG_ERROR, "in getsockname(%d): %s", fd,
						strerror(errno));
				free(ip);
				return NULL;
			}
		}
		ret = inet_ntop(AF_INET6, &(addr6.sin6_addr), ip, 64);
		if (ret == NULL) {
			mylog(LOG_ERROR, "in inet_ntop: %s", strerror(errno));
			free(ip);
			return NULL;
		}
		break;
	default:
		mylog(LOG_ERROR, "Unknown socket family, that's bad.");
		free(ip);
		return NULL;
	}
	return ip;
}

char *connection_localip(connection_t *cn)
{
	if (cn->handle <= 0)
		return NULL;

	return socket_ip(cn->handle, 0);
}

char *connection_remoteip(connection_t *cn)
{
	if (cn->handle <= 0)
		return NULL;

	return socket_ip(cn->handle, 1);
}
