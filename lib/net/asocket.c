/* Copyright 2016 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"           // for VERSION, _LARGE_FILES, etc

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/uio.h>
#include <unistd.h>
#include <event2/event.h>               // for event_free, event_base_new, etc
#include <ccoin/buffer.h>
#include <ccoin/clist.h>
#include <ccoin/parr.h>
#include <ccoin/net/asocket.h>
#include <ccoin/net/netbase.h>

static void asocket_rx_on(struct asocket *);
static void asocket_tx_on(struct asocket *);
static void asocket_rx_off(struct asocket *);
static void asocket_tx_off(struct asocket *);

static bool setnonblock(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags < 0)
		return false;
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0)
		return false;

        return true;
}

void asocket_init(struct asocket *as, const struct asocket_cfg *cfg)
{
	memset(as, 0, sizeof(*as));
	as->fd = -1;
	as->error = false;
	as->cfg = cfg;
}

void asocket_free(struct asocket *as)
{
	if (!as)
		return;

	asocket_rx_off(as);
	asocket_tx_off(as);

	if (as->fd >= 0) {
		close(as->fd);
		as->fd = -1;
	}
}

void asocket_freep(void *p)
{
	struct asocket *as = p;
	if (!as)
		return;

	asocket_free(as);

	memset(as, 0, sizeof(*as));
	free(as);
}

void asocket_close(struct asocket *as)
{
	assert(as->fd >= 0);

	asocket_rx_off(as);
	asocket_tx_off(as);

	close(as->fd);
	as->fd = -1;

	if (as->cfg->as_close)
		as->cfg->as_close(as, as->cfg->priv, as->error);
}

static void asocket_err(struct asocket *as, int err)
{
	as->error = true;

	if (as->cfg->as_error)
		as->cfg->as_error(as, as->cfg->priv, err);

	asocket_close(as);
}

static void asocket_end(struct asocket *as)
{
	if (as->cfg->as_end)
		as->cfg->as_end(as, as->cfg->priv);

	asocket_close(as);
}

static void asocket_build_iov(clist *write_q, unsigned int partial,
			      struct iovec **iov_, unsigned int *iov_len_)
{
	*iov_ = NULL;
	*iov_len_ = 0;

	// Allocate IOV for entire write queue
	unsigned int i, iov_len = clist_length(write_q);
	struct iovec *iov = calloc(iov_len, sizeof(struct iovec));

	clist *tmp = write_q;

	// Fill scatter-gather segments from write queue
	i = 0;
	while (tmp) {
		struct buffer *buf = tmp->data;

		iov[i].iov_base = buf->p;
		iov[i].iov_len = buf->len;

		// If first element, adjust for partial write already completed
		if (i == 0) {
			iov[0].iov_base += partial;
			iov[0].iov_len -= partial;
		}

		tmp = tmp->next;
		i++;
	}

	// Return allocated iov
	*iov_ = iov;
	*iov_len_ = iov_len;
}

size_t asocket_writeq_sz(const struct asocket *as)
{
	size_t res = 0;

	// Walk list, summing each buffer length
	clist *tmp = as->write_q;
	bool first = true;
	while (tmp) {
		struct buffer *buf = tmp->data;

		// If first element, adjust for partial write already completed
		if (first) {
			res += (buf->len - as->write_partial);
			first = false;
		} else {
			res += buf->len;
		}

		tmp = tmp->next;
	}

	return res;
}

static void asocket_written(struct asocket *as, size_t bytes)
{
	// Global stats
	as->bytes_written += bytes;

	// Consume N buffers, whose total size is <= 'bytes'
	while (bytes > 0) {
		clist *tmp;
		struct buffer *buf;
		unsigned int left;

		tmp = as->write_q;
		buf = tmp->data;
		left = buf->len - as->write_partial;

		/* buffer fully written; free */
		if (bytes >= left) {
			free(buf->p);
			free(buf);
			as->write_partial = 0;
			as->write_q = clist_delete(tmp, tmp);

			bytes -= left;
		}

		/* buffer partially written; store state */
		else {
			as->write_partial += bytes;
			break;
		}
	}
}

static void asocket_write_cb(evutil_socket_t fd, short events, void *priv)
{
	struct asocket *as = priv;
	struct iovec *iov = NULL;
	unsigned int iov_len = 0;

	/* build list of outgoing data buffers */
	asocket_build_iov(as->write_q, as->write_partial, &iov, &iov_len);

	/* send data to network */
	ssize_t wrc = writev(as->fd, iov, iov_len);

	free(iov);

	// Return if blocking needed; abort if other error.
	if (wrc < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			asocket_err(as, errno);
		return;
	}

	/* handle partially and fully completed buffers */
	asocket_written(as, wrc);

	// thaw read, if write queue fully drained
	if (!as->write_q) {
		asocket_tx_off(as);
		asocket_rx_on(as);

		if (as->cfg->as_drain)
			as->cfg->as_drain(as, as->cfg->priv);
	}
}

static bool asocket_write_buf(struct asocket *as, struct buffer *buf)
{
	/* if write q exists, write_evt will handle output */
	if (as->write_q) {
		as->write_q = clist_append(as->write_q, buf);
		return true;
	}

	/* attempt optimistic write */
	ssize_t wrc = write(as->fd, buf->p, buf->len);

	if (wrc < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			buffer_free(buf);

			// TODO: asocket_err() ?
			return false;
		}

		/* write would block; queue */
		as->write_q = clist_append(as->write_q, buf);
	} else {
		as->bytes_written += wrc;

		/* optimism rewarded! message fully sent to kernel queue. */
		if (wrc == buf->len) {
			// TODO: call ->as_drain() ?
			buffer_free(buf);
			return true;
		}

		/* message partially sent */
		as->write_q = clist_append(as->write_q, buf);
		as->write_partial = wrc;
	}

	/* pause read; poll for writable */
	asocket_rx_off(as);
	asocket_tx_on(as);
	return true;
}

bool asocket_write(struct asocket *as, const void *p, size_t len)
{
	// Copy data
	struct buffer *buf = buffer_copy(p, len);
	if (!buf)
		return false;

	// Hand buffer ownership to write queue
	return asocket_write_buf(as, buf);
}

static void asocket_read_cb(evutil_socket_t fd, short events, void *userpriv)
{
	struct asocket *as = userpriv;
	assert(events & EV_READ);

	ssize_t bread;
	char buf[4096];
	do {

		// Read data from kernel buffer
		bread = read(fd, buf, sizeof(buf));

		// Return if blocking needed; abort if other error.
		if (bread < 0) {
			if ((errno != EAGAIN) && (errno != EWOULDBLOCK))
				asocket_err(as, errno);
			return;
		}

		// End of file signalled
		if (bread == 0) {
			asocket_end(as);
			return;
		}

		// Global stats
		as->bytes_read += bread;

		// Indicate data available on socket
		struct const_buffer cbuf = { buf, bread };
		if (as->cfg->as_data)
			as->cfg->as_data(as, as->cfg->priv, &cbuf);
	} while (bread == sizeof(buf));
}

static void turn_off_event(struct event **ev_io)
{
	struct event *ev = *ev_io;

	if (!ev)
		return;

	int rc = event_del(ev);
	assert(rc == 0);

	event_free(ev);
	*ev_io = NULL;
}

static void asocket_rx_off(struct asocket *as)
{
	turn_off_event(&as->ev);
}

static void asocket_tx_off(struct asocket *as)
{
	turn_off_event(&as->write_ev);
}

static void asocket_rx_on(struct asocket *as)
{
	assert(as != NULL);

	if (as->ev)
		return;

	as->ev = event_new(as->cfg->eb, as->fd, EV_READ | EV_PERSIST,
			   asocket_read_cb, as);
	if (!as->ev) {
		as->error = true;
		return;
	}

	if (event_add(as->ev, NULL) != 0) {
		event_free(as->ev);
		as->ev = NULL;
		as->error = true;
	}
}

static void asocket_tx_on(struct asocket *as)
{
	assert(as != NULL);

	if (as->write_ev)
		return;

	as->write_ev = event_new(as->cfg->eb, as->fd, EV_WRITE | EV_PERSIST,
				 asocket_write_cb, as);
	if (!as->write_ev) {
		as->error = true;
		return;
	}

	if (event_add(as->write_ev, NULL) != 0) {
		event_free(as->write_ev);
		as->write_ev = NULL;
		as->error = true;
	}
}

static void asocket_connect_cb(evutil_socket_t fd, short events, void *userpriv)
{
	struct asocket *as = userpriv;
	int v = 0;
	socklen_t v_len = sizeof(v);

	as->connecting = false;

	// Check for connect(2) error
	int rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &v, &v_len);
	if (rc < 0) {
		asocket_err(as, errno);
		return;
	}
	if (v != 0) {
		asocket_err(as, v);
		return;
	}

	// Release fired event
	event_free(as->ev);
	as->ev = NULL;

	// Trigger event callback
	if (as->cfg->as_connect)
		as->cfg->as_connect(as, as->cfg->priv);

	// Enable input data from remote peer
	asocket_rx_on(as);
}

static bool asocket_open(struct asocket *as, bool is_v4)
{
	int sock_domain = is_v4 ? AF_INET : AF_INET6;

	assert(as->fd < 0);

	// Open non-blocking stream socket
	as->fd = socket(sock_domain, SOCK_STREAM, IPPROTO_TCP);
	if (as->fd < 0)
		return false;
	if (!setnonblock(as->fd)) {
		close(as->fd);
		as->fd = -1;
		return false;
	}

	as->is_v4 = is_v4;
	return true;
}

static void asocket_name(struct asocket *as, const struct sockaddr *saddr,
			 socklen_t salen)
{
	char host[128];
	char serv[16];

	int rc = getnameinfo(saddr, salen,
			     host, sizeof(host), serv, sizeof(serv),
			     NI_NUMERICHOST | NI_NUMERICSERV);
	assert(rc == 0);

	if (as->is_v4) {
		struct sockaddr_in *sin = (struct sockaddr_in *) saddr;
		assert(salen >= sizeof(struct sockaddr_in));
		memcpy(as->addr, ipv4_mapped_pfx, sizeof(ipv4_mapped_pfx));
		memcpy(as->addr + 12, &sin->sin_addr.s_addr, 4);

		snprintf(as->addr_str, sizeof(as->addr_str), "%s:%s",
			 host, serv);
	} else {
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *) saddr;
		assert(salen >= sizeof(struct sockaddr_in6));
		memcpy(as->addr, &sin->sin6_addr.s6_addr, 16);

		snprintf(as->addr_str, sizeof(as->addr_str), "[%s]:%s",
			 host, serv);
	}
}

bool asocket_connect(struct asocket *as, const struct asocket_opt *opt)
{
	if (!as || !opt)
		return false;

	// Pick (default) hostname for remote peer
	bool is_v4 = (opt->family == 6) ? false : true;
	const char *host = opt->host;
	if (!host) {
		if (opt->family == 6)
			host = "::1";
		else
			host = "127.0.0.1";
	}

	// Fill hints for getaddrinfo(3) query limiting
	int sock_domain = is_v4 ? AF_INET : AF_INET6;
	struct addrinfo hints = {
		.ai_family		= sock_domain,
		.ai_socktype		= SOCK_STREAM,
		.ai_protocol		= IPPROTO_TCP,
		.ai_flags		= AI_NUMERICHOST | AI_NUMERICSERV,
	};
	struct addrinfo *res = NULL;

	// Parse host/port strings -> network addresses
	int rc = getaddrinfo(host, opt->port, &hints, &res);
	if (rc != 0)
		return false;

	// Open non-blocking stream socket
	assert(as->fd < 0);
	if (!asocket_open(as, is_v4)) {
		freeaddrinfo(res);
		return false;
	}

	// Build bitcoin-parsable + human readable addresses
	asocket_name(as, res->ai_addr, res->ai_addrlen);

	// Initiate non-blocking connection to remote peer
	rc = connect(as->fd, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	// Abort upon immediate error
	if ((rc < 0) && (errno != EINPROGRESS)) {
		as->error = true;
		return false;
	}

	// Signal transition to connecting state
	as->connecting = true;

	// Wait for connection event
	as->ev = event_new(as->cfg->eb, as->fd, EV_WRITE,
			   asocket_connect_cb, as);
	assert(as->ev != NULL);

	rc = event_add(as->ev, NULL);
	assert(rc == 0);

	return true;
}

static void asocket_accepted(struct asocket *as, const struct asocket *parent,
			     int fd, struct sockaddr *saddr, socklen_t salen)
{
	assert(as->fd == -1);
	assert(as->cfg != NULL);
	assert(as->opt == NULL);

	// Initialize from existing socket/fd
	as->fd = fd;
	as->is_v4 = parent->is_v4;
	asocket_name(as, saddr, salen);

	// Enable input data from remote peer
	asocket_rx_on(as);
}

static void srv_sock_close(struct asocket *as, void *srv_p, bool had_err)
{
	struct aserver *srv = srv_p;

	if (srv->cfg->srv_close)
		srv->cfg->srv_close(srv, srv->cfg->priv, had_err);
}

static void srv_sock_error(struct asocket *as, void *srv_p, int err)
{
	struct aserver *srv = srv_p;

	if (srv->cfg->srv_error)
		srv->cfg->srv_error(srv, srv->cfg->priv, err);
}

void aserver_init(struct aserver *srv, const struct aserver_cfg *cfg,
		  const struct asocket_cfg *accepted_cfg)
{
	memset(srv, 0, sizeof(*srv));

	struct asocket_cfg tmpcfg = {
		.eb		= cfg->eb,
		.priv		= srv,
		.as_close	= srv_sock_close,
		.as_error	= srv_sock_error,
	};

	asocket_init(&srv->sock, &srv->srv_sock_cfg);
	srv->srv_sock_cfg = tmpcfg;
	srv->cfg = cfg;
	srv->accepted_cfg = accepted_cfg;
	srv->cxn = parr_new(0, asocket_freep);
}

void aserver_free(struct aserver *srv)
{
	if (!srv)
		return;

	asocket_free(&srv->sock);
}

void aserver_freep(void *p)
{
	struct aserver *srv = p;
	if (!srv)
		return;

	aserver_free(srv);

	memset(srv, 0, sizeof(*srv));
	free(srv);
}

static void aserver_accept_cb(evutil_socket_t fd, short events, void *userpriv)
{
	struct aserver *srv = userpriv;
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);

	int in_fd = accept(fd, (struct sockaddr *) &addr, &addr_len);
	if (in_fd < 0) {
		asocket_err(&srv->sock, errno);
		return;
	}

	struct asocket *cli_sock = calloc(1, sizeof(*cli_sock));
	if (!cli_sock) {
		close(in_fd);
		asocket_err(&srv->sock, ENOMEM);
		return;
	}

	asocket_init(cli_sock, srv->accepted_cfg);
	asocket_accepted(cli_sock, &srv->sock, in_fd,
			 (struct sockaddr *) &addr, addr_len);

	parr_add(srv->cxn, cli_sock);

	if (srv->cfg->srv_accepted)
		srv->cfg->srv_accepted(srv, srv->cfg->priv);
}

bool aserver_listen(struct aserver *srv, const struct asocket_opt *opt)
{
	if (!srv || !opt)
		return false;

	struct asocket *as = &srv->sock;

	// Pick (default) hostname for remote peer
	bool is_v4 = (opt->family == 6) ? false : true;

	// Fill hints for getaddrinfo(3) query limiting
	int sock_domain = is_v4 ? AF_INET : AF_INET6;
	struct addrinfo hints = {
		.ai_family		= sock_domain,
		.ai_socktype		= SOCK_STREAM,
		.ai_protocol		= IPPROTO_TCP,
		.ai_flags		= AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV,
	};
	struct addrinfo *res = NULL;

	// Parse host/port strings -> network addresses
	int rc = getaddrinfo(opt->host, opt->port, &hints, &res);
	if (rc != 0)
		return false;

	// Open non-blocking stream socket
	assert(as->fd < 0);
	if (!asocket_open(as, is_v4)) {
		freeaddrinfo(res);
		return false;
	}

	// Build bitcoin-parsable + human readable addresses
	asocket_name(as, res->ai_addr, res->ai_addrlen);

	// Bind to (address?) and port
	rc = bind(as->fd, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	// Abort upon immediate error
	if (rc < 0) {
		as->error = true;
		return false;
	}

	// Starting listening on address/port
	rc = listen(as->fd, 100);
	if (rc < 0) {
		as->error = true;
		return false;
	}

	// Wait for connection event
	as->ev = event_new(as->cfg->eb, as->fd, EV_READ | EV_PERSIST,
			   aserver_accept_cb, srv);
	assert(as->ev != NULL);

	rc = event_add(as->ev, NULL);
	assert(rc == 0);

	if (srv->cfg->srv_listening)
		srv->cfg->srv_listening(srv, srv->cfg->priv);

	return true;
}

