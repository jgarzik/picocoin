/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#include <openssl/rand.h>
#include <event2/event.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/buint.h>
#include <ccoin/blkdb.h>
#include <ccoin/message.h>
#include <ccoin/mbr.h>
#include <ccoin/script.h>
#include <ccoin/net.h>
#include <ccoin/hashtab.h>
#include <ccoin/hexcode.h>
#include "peerman.h"
#include "brd.h"

struct bp_hashtab *settings;
const struct chain_info *chain = NULL;
bu256_t chain_genesis;
uint64_t instance_nonce;
bool debugging = false;
FILE *plog = NULL;

static struct blkdb db;
static struct bp_hashtab *orphans;
static struct bp_utxo_set uset;
static int blocks_fd = -1;
static bool script_verf = false;
static bool daemon_running = true;
struct net_child_info global_nci;



static const char *const_settings[] = {
	"net.connect.timeout=11",
	"chain=bitcoin",
	"peers=brd.peers",
	/* "blkdb=brd.blkdb", */
	"blocks=brd.blocks",
	"log=-", /* "log=brd.log", */
};

struct net_child_info {
	int			read_fd;
	int			write_fd;

	struct peer_manager	*peers;

	parr		*conns;
	struct event_base	*eb;

	time_t			last_getblocks;
};

struct nc_conn {
	bool			dead;

	int			fd;

	struct peer		peer;
	char			addr_str[64];

	bool			ipv4;
	bool			connected;
	struct event		*ev;
	struct net_child_info	*nci;

	struct event		*write_ev;
	clist			*write_q;	/* of struct buffer */
	unsigned int		write_partial;

	struct p2p_message	msg;

	void			*msg_p;
	unsigned int		expected;
	bool			reading_hdr;
	unsigned char		hdrbuf[P2P_HDR_SZ];

	bool			seen_version;
	bool			seen_verack;
	uint32_t		protover;
};


enum {
	NC_MAX_CONN		= 8,
};

static unsigned int net_conn_timeout = 11;

static void nc_conn_kill(struct nc_conn *conn);
static bool nc_conn_read_enable(struct nc_conn *conn);
static bool nc_conn_read_disable(struct nc_conn *conn);
static bool nc_conn_write_enable(struct nc_conn *conn);
static bool nc_conn_write_disable(struct nc_conn *conn);

static bool process_block(const struct bp_block *block, int64_t fpos);
static bool have_orphan(const bu256_t *v);
static bool add_orphan(const bu256_t *hash_in, struct const_buffer *buf_in);

static void nc_conn_build_iov(clist *write_q, unsigned int partial,
			      struct iovec **iov_, unsigned int *iov_len_)
{
	*iov_ = NULL;
	*iov_len_ = 0;

	unsigned int i, iov_len = clist_length(write_q);
	struct iovec *iov = calloc(iov_len, sizeof(struct iovec));

	clist *tmp = write_q;

	i = 0;
	while (tmp) {
		struct buffer *buf = tmp->data;

		iov[i].iov_base = buf->p;
		iov[i].iov_len = buf->len;

		if (i == 0) {
			iov[0].iov_base += partial;
			iov[0].iov_len -= partial;
		}

		tmp = tmp->next;
		i++;
	}

	*iov_ = iov;
	*iov_len_ = iov_len;
}

static void nc_conn_written(struct nc_conn *conn, size_t bytes)
{
	while (bytes > 0) {
		clist *tmp;
		struct buffer *buf;
		unsigned int left;

		tmp = conn->write_q;
		buf = tmp->data;
		left = buf->len - conn->write_partial;

		/* buffer fully written; free */
		if (bytes >= left) {
			free(buf->p);
			free(buf);
			conn->write_partial = 0;
			conn->write_q = clist_delete(tmp, tmp);

			bytes -= left;
		}

		/* buffer partially written; store state */
		else {
			conn->write_partial += bytes;
			break;
		}
	}
}

static void nc_conn_write_evt(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;
	struct iovec *iov = NULL;
	unsigned int iov_len = 0;

	/* build list of outgoing data buffers */
	nc_conn_build_iov(conn->write_q, conn->write_partial, &iov, &iov_len);

	/* send data to network */
	ssize_t wrc = writev(conn->fd, iov, iov_len);

	free(iov);

	if (wrc < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK)
			goto err_out;
		return;
	}

	/* handle partially and fully completed buffers */
	nc_conn_written(conn, wrc);

	/* thaw read, if write fully drained */
	if (!conn->write_q) {
		nc_conn_write_disable(conn);
		nc_conn_read_enable(conn);
	}

	return;

err_out:
	nc_conn_kill(conn);
}

static bool nc_conn_send(struct nc_conn *conn, const char *command,
			 const void *data, size_t data_len)
{
	/* build wire message */
	cstring *msg = message_str(chain->netmagic, command, data, data_len);
	if (!msg)
		return false;

	/* buffer now owns message data */
	struct buffer *buf = calloc(1, sizeof(struct buffer));
	buf->p = msg->str;
	buf->len = msg->len;

	cstr_free(msg, false);

	/* if write q exists, write_evt will handle output */
	if (conn->write_q) {
		conn->write_q = clist_append(conn->write_q, buf);
		return true;
	}

	/* attempt optimistic write */
	ssize_t wrc = write(conn->fd, buf->p, buf->len);

	if (wrc < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK) {
			free(buf->p);
			free(buf);
			return false;
		}

		conn->write_q = clist_append(conn->write_q, buf);
		goto out_wrstart;
	}

	/* message fully sent */
	if (wrc == buf->len) {
		free(buf->p);
		free(buf);
		return true;
	}

	/* message partially sent; pause read; poll for writable */
	conn->write_q = clist_append(conn->write_q, buf);
	conn->write_partial = wrc;

out_wrstart:
	nc_conn_read_disable(conn);
	nc_conn_write_enable(conn);
	return true;
}

static bool nc_msg_version(struct nc_conn *conn)
{
	if (conn->seen_version)
		return false;
	conn->seen_version = true;

	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_version mv;
	bool rc = false;

	msg_version_init(&mv);

	if (!deser_msg_version(&mv, &buf))
		goto out;

	if (debugging) {
		char fromstr[64], tostr[64];
		bn_address_str(fromstr, sizeof(fromstr), mv.addrFrom.ip);
		bn_address_str(tostr, sizeof(tostr), mv.addrTo.ip);
		fprintf(plog, "net: %s version(%u, 0x%llx, %lld, To:%s, From:%s, %s, %u)\n",
			conn->addr_str,
			mv.nVersion,
			(unsigned long long) mv.nServices,
			(long long) mv.nTime,
			tostr,
			fromstr,
			mv.strSubVer,
			mv.nStartingHeight);
	}

	if (!(mv.nServices & NODE_NETWORK))	/* require NODE_NETWORK */
		goto out;
	if (mv.nonce == instance_nonce)		/* connected to ourselves? */
		goto out;

	conn->protover = MIN(mv.nVersion, PROTO_VERSION);

	/* acknowledge version receipt */
	if (!nc_conn_send(conn, "verack", NULL, 0))
		goto out;

	rc = true;

out:
	msg_version_free(&mv);
	return rc;
}

static bool nc_msg_addr(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_addr ma;
	bool rc = false;

	msg_addr_init(&ma);

	if (!deser_msg_addr(conn->protover, &ma, &buf))
		goto out;

	unsigned int i;
	time_t cutoff = time(NULL) - (7 * 24 * 60 * 60);
	if (debugging) {
		unsigned int old = 0;
		for (i = 0; i < ma.addrs->len; i++) {
			struct bp_address *addr = parr_idx(ma.addrs, i);
			if (addr->nTime < cutoff)
				old++;
		}
		fprintf(plog, "net: %s addr(%zu addresses, %u old)\n",
			conn->addr_str, ma.addrs->len, old);
	}

	/* ignore ancient addresses */
	if (conn->protover < CADDR_TIME_VERSION)
		goto out_ok;

	/* feed addresses to peer manager */
	for (i = 0; i < ma.addrs->len; i++) {
		struct bp_address *addr = parr_idx(ma.addrs, i);
		if (addr->nTime > cutoff)
			peerman_add_addr(conn->nci->peers, addr, false);
	}

out_ok:
	rc = true;

out:
	msg_addr_free(&ma);
	return rc;
}

static bool nc_msg_verack(struct nc_conn *conn)
{
	if (conn->seen_verack)
		return false;
	conn->seen_verack = true;

	if (debugging)
		fprintf(plog, "net: %s verack\n",
			conn->addr_str);

	/*
	 * When a connection attempt is made, the peer is deleted
	 * from the peer list.  When we successfully connect,
	 * the peer is re-added.  Thus, peers are immediately
	 * forgotten if they fail, on the first try.
	 */
	conn->peer.last_ok = time(NULL);
	conn->peer.n_ok++;
	conn->peer.addr.nTime = (uint32_t) conn->peer.last_ok;
	peerman_add(conn->nci->peers, &conn->peer, true);

	/* request peer addresses */
	if ((conn->protover >= CADDR_TIME_VERSION) &&
	    (!nc_conn_send(conn, "getaddr", NULL, 0)))
		return false;

	/* request blocks */
	bool rc = true;
	time_t now = time(NULL);
	time_t cutoff = now - (24 * 60 * 60);
	if (conn->nci->last_getblocks < cutoff) {
		struct msg_getblocks gb;
		msg_getblocks_init(&gb);
		blkdb_locator(&db, NULL, &gb.locator);
		cstring *s = ser_msg_getblocks(&gb);

		rc = nc_conn_send(conn, "getblocks", s->str, s->len);

		cstr_free(s, true);
		msg_getblocks_free(&gb);

		conn->nci->last_getblocks = now;
	}

	return rc;
}

static bool nc_msg_inv(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct msg_vinv mv, mv_out;
	bool rc = false;

	msg_vinv_init(&mv);
	msg_vinv_init(&mv_out);

	if (!deser_msg_vinv(&mv, &buf))
		goto out;

	if (debugging && mv.invs && mv.invs->len == 1) {
		struct bp_inv *inv = parr_idx(mv.invs, 0);
		char hexstr[BU256_STRSZ];
		bu256_hex(hexstr, &inv->hash);

		char typestr[32];
		switch (inv->type) {
		case MSG_TX: strcpy(typestr, "tx"); break;
		case MSG_BLOCK: strcpy(typestr, "block"); break;
		default: sprintf(typestr, "unknown 0x%x", inv->type); break;
		}

		fprintf(plog, "net: %s inv %s %s\n",
			conn->addr_str, typestr, hexstr);
	}
	else if (debugging && mv.invs) {
		fprintf(plog, "net: %s inv (%zu sz)\n",
			conn->addr_str, mv.invs->len);
	}

	if (!mv.invs || !mv.invs->len)
		goto out_ok;

	/* scan incoming inv's for interesting material */
	unsigned int i;
	for (i = 0; i < mv.invs->len; i++) {
		struct bp_inv *inv = parr_idx(mv.invs, i);
		switch (inv->type) {
		case MSG_BLOCK:
			if (!blkdb_lookup(&db, &inv->hash) &&
			    !have_orphan(&inv->hash))
				msg_vinv_push(&mv_out, MSG_BLOCK, &inv->hash);
			break;

		case MSG_TX:
		default:
			break;
		}
	}

	/* send getdata, if they have anything we want */
	if (mv_out.invs && mv_out.invs->len) {
		cstring *s = ser_msg_vinv(&mv_out);

		rc = nc_conn_send(conn, "getdata", s->str, s->len);

		cstr_free(s, true);
	}

out_ok:
	rc = true;

out:
	msg_vinv_free(&mv);
	msg_vinv_free(&mv_out);
	return rc;
}

static bool nc_msg_block(struct nc_conn *conn)
{
	struct const_buffer buf = { conn->msg.data, conn->msg.hdr.data_len };
	struct bp_block block;
	bp_block_init(&block);

	bool rc = false;

	if (!deser_bp_block(&block, &buf))
		goto out;
	bp_block_calc_sha256(&block);
	char hexstr[BU256_STRSZ];
	bu256_hex(hexstr, &block.sha256);

	if (debugging) {
		fprintf(plog, "net: %s block %s\n",
			conn->addr_str,
			hexstr);
	}

	if (!bp_block_valid(&block)) {
		fprintf(plog, "net: %s invalid block %s\n",
			conn->addr_str,
			hexstr);
		goto out;
	}

	/* check for duplicate block */
	if (blkdb_lookup(&db, &block.sha256) ||
	    have_orphan(&block.sha256))
		goto out_ok;

	struct iovec iov[2];
	iov[0].iov_base = &conn->msg.hdr;	// TODO: endian bug?
	iov[0].iov_len = sizeof(conn->msg.hdr);
	iov[1].iov_base = (void *) buf.p;	// cast away 'const'
	iov[1].iov_len = buf.len;
	size_t total_write = iov[0].iov_len + iov[1].iov_len;

	/* store current file position */
	off64_t fpos64 = lseek64(blocks_fd, 0, SEEK_CUR);
	if (fpos64 == (off64_t)-1) {
		fprintf(plog, "blocks: lseek64 failed %s\n",
			strerror(errno));
		goto out;
	}

	/* write new block to disk */
	errno = 0;
	ssize_t bwritten = writev(blocks_fd, iov, ARRAY_SIZE(iov));
	if (bwritten != total_write) {
		fprintf(plog, "blocks: write failed %s\n",
			strerror(errno));
		goto out;
	}

	/* process block */
	if (!process_block(&block, fpos64)) {
		fprintf(plog, "blocks: process-block failed\n");
		goto out;
	}

out_ok:
	rc = true;

out:
	bp_block_free(&block);
	return rc;
}

static bool nc_conn_message(struct nc_conn *conn)
{
	char *command = conn->msg.hdr.command;

	/* verify correct network */
	if (memcmp(conn->msg.hdr.netmagic, chain->netmagic, 4)) {
		fprintf(plog, "net: %s invalid network\n",
			conn->addr_str);
		return false;
	}

	/* incoming message: version */
	if (!strncmp(command, "version", 12))
		return nc_msg_version(conn);

	/* "version" must be first message */
	if (!conn->seen_version) {
		fprintf(plog, "net: %s 'version' not first\n",
			conn->addr_str);
		return false;
	}

	/* incoming message: verack */
	if (!strncmp(command, "verack", 12))
		return nc_msg_verack(conn);

	/* "verack" must be second message */
	if (!conn->seen_verack) {
		fprintf(plog, "net: %s 'verack' not second\n",
			conn->addr_str);
		return false;
	}

	/* incoming message: addr */
	if (!strncmp(command, "addr", 12))
		return nc_msg_addr(conn);

	/* incoming message: inv */
	else if (!strncmp(command, "inv", 12))
		return nc_msg_inv(conn);

	/* incoming message: block */
	else if (!strncmp(command, "block", 12))
		return nc_msg_block(conn);

	if (debugging)
		fprintf(plog, "net: %s unknown message %s\n",
			conn->addr_str,
			command);

	/* ignore unknown messages */
	return true;
}

static bool nc_conn_ip_active(struct net_child_info *nci,
			      const unsigned char *ip)
{
	unsigned int i;
	for (i = 0; i < nci->conns->len; i++) {
		struct nc_conn *conn;

		conn = parr_idx(nci->conns, i);
		if (!memcmp(conn->peer.addr.ip, ip, 16))
			return true;
	}

	return false;
}

static bool nc_conn_group_active(struct net_child_info *nci,
				 const struct peer *peer)
{
	// FIXME
	return false;

	unsigned int group_len = peer->group_len;
	unsigned int i;
	for (i = 0; i < nci->conns->len; i++) {
		struct nc_conn *conn;

		conn = parr_idx(nci->conns, i);
		if ((group_len == conn->peer.group_len) &&
		    !memcmp(peer->group, conn->peer.group, group_len))
			return true;
	}

	return false;
}

static struct nc_conn *nc_conn_new(const struct peer *peer)
{
	struct nc_conn *conn;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;

	conn->fd = -1;

	peer_copy(&conn->peer, peer);
	bn_address_str(conn->addr_str, sizeof(conn->addr_str), conn->peer.addr.ip);

	return conn;
}

static void nc_conn_kill(struct nc_conn *conn)
{
	assert(conn->dead == false);

	conn->dead = true;
	event_base_loopbreak(conn->nci->eb);
}

static void nc_conn_free(struct nc_conn *conn)
{
	if (!conn)
		return;

	if (conn->write_q) {
		clist *tmp = conn->write_q;

		while (tmp) {
			struct buffer *buf;

			buf = tmp->data;
			tmp = tmp->next;

			free(buf->p);
			free(buf);
		}

		clist_free(conn->write_q);
	}

	if (conn->ev) {
		event_del(conn->ev);
		event_free(conn->ev);
	}
	if (conn->write_ev) {
		event_del(conn->write_ev);
		event_free(conn->write_ev);
	}

	if (conn->fd >= 0)
		close(conn->fd);

	free(conn->msg.data);

	memset(conn, 0, sizeof(*conn));
	free(conn);
}

static bool nc_conn_start(struct nc_conn *conn)
{
	char errpfx[64];

	/* create socket */
	conn->ipv4 = is_ipv4_mapped(conn->peer.addr.ip);
	conn->fd = socket(conn->ipv4 ? AF_INET : AF_INET6,
			  SOCK_STREAM, IPPROTO_TCP);
	if (conn->fd < 0) {
		sprintf(errpfx, "socket %s", conn->addr_str);
		perror(errpfx);
		return false;
	}

	/* set non-blocking */
	int flags = fcntl(conn->fd, F_GETFL, 0);
	if ((flags < 0) ||
	    (fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK) < 0)) {
		sprintf(errpfx, "socket fcntl %s", conn->addr_str);
		perror(errpfx);
		return false;
	}

	struct sockaddr *saddr;
	struct sockaddr_in6 saddr6;
	struct sockaddr_in saddr4;
	socklen_t saddr_len;

	/* fill out connect(2) address */
	if (conn->ipv4) {
		memset(&saddr4, 0, sizeof(saddr4));
		saddr4.sin_family = AF_INET;
		memcpy(&saddr4.sin_addr.s_addr,
		       &conn->peer.addr.ip[12], 4);
		saddr4.sin_port = htons(conn->peer.addr.port);

		saddr = (struct sockaddr *) &saddr4;
		saddr_len = sizeof(saddr4);
	} else {
		memset(&saddr6, 0, sizeof(saddr6));
		saddr6.sin6_family = AF_INET6;
		memcpy(&saddr6.sin6_addr.s6_addr,
		       &conn->peer.addr.ip[0], 16);
		saddr6.sin6_port = htons(conn->peer.addr.port);

		saddr = (struct sockaddr *) &saddr6;
		saddr_len = sizeof(saddr6);
	}

	/* initiate TCP connection */
	if (connect(conn->fd, saddr, saddr_len) < 0) {
		if (errno != EINPROGRESS) {
			sprintf(errpfx, "socket connect %s", conn->addr_str);
			perror(errpfx);
			return false;
		}
	}

	return true;
}

static bool nc_conn_got_header(struct nc_conn *conn)
{
	parse_message_hdr(&conn->msg.hdr, conn->hdrbuf);

	unsigned int data_len = conn->msg.hdr.data_len;

	if (data_len > (16 * 1024 * 1024)) {
		free(conn->msg.data);
		conn->msg.data = NULL;
		return false;
	}

	conn->msg.data = malloc(data_len);

	/* switch to read-body state */
	conn->msg_p = conn->msg.data;
	conn->expected = data_len;
	conn->reading_hdr = false;

	return true;
}

static bool nc_conn_got_msg(struct nc_conn *conn)
{
	if (!message_valid(&conn->msg)) {
		fprintf(plog, "llnet: %s invalid message\n",
			conn->addr_str);
		return false;
	}

	if (!nc_conn_message(conn))
		return false;

	free(conn->msg.data);
	conn->msg.data = NULL;

	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;

	return true;
}

static void nc_conn_read_evt(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;

	ssize_t rrc = read(fd, conn->msg_p, conn->expected);
	if (rrc <= 0) {
		if (rrc < 0)
			fprintf(plog, "llnet: %s read: %s\n",
				conn->addr_str,
				strerror(errno));
		else
			fprintf(plog, "llnet: %s read EOF\n", conn->addr_str);

		goto err_out;
	}

	conn->msg_p += rrc;
	conn->expected -= rrc;

	/* execute our state machine at most twice */
	unsigned int i;
	for (i = 0; i < 2; i++) {
		if (conn->expected == 0) {
			if (conn->reading_hdr) {
				if (!nc_conn_got_header(conn))
					goto err_out;
			} else {
				if (!nc_conn_got_msg(conn))
					goto err_out;
			}
		}
	}

	return;

err_out:
	nc_conn_kill(conn);
}

static cstring *nc_version_build(struct nc_conn *conn)
{
	struct msg_version mv;

	msg_version_init(&mv);

	mv.nVersion = PROTO_VERSION;
	mv.nServices = blocks_fd >= 0 ? NODE_NETWORK : 0;
	mv.nTime = (int64_t) time(NULL);
	mv.nonce = instance_nonce;
	sprintf(mv.strSubVer, "/brd:%s/", VERSION);
	mv.nStartingHeight = db.best_chain ? db.best_chain->height : 0;

	cstring *rs = ser_msg_version(&mv);

	msg_version_free(&mv);

	return rs;
}

static bool nc_conn_read_enable(struct nc_conn *conn)
{
	if (conn->ev)
		return true;

	conn->ev = event_new(conn->nci->eb, conn->fd, EV_READ | EV_PERSIST,
			     nc_conn_read_evt, conn);
	if (!conn->ev)
		return false;

	if (event_add(conn->ev, NULL) != 0) {
		event_free(conn->ev);
		conn->ev = NULL;
		return false;
	}

	return true;
}

static bool nc_conn_read_disable(struct nc_conn *conn)
{
	if (!conn->ev)
		return true;

	event_del(conn->ev);
	event_free(conn->ev);

	conn->ev = NULL;

	return true;
}

static bool nc_conn_write_enable(struct nc_conn *conn)
{
	if (conn->write_ev)
		return true;

	conn->write_ev = event_new(conn->nci->eb, conn->fd,
				   EV_WRITE | EV_PERSIST,
				   nc_conn_write_evt, conn);
	if (!conn->write_ev)
		return false;

	if (event_add(conn->write_ev, NULL) != 0) {
		event_free(conn->write_ev);
		conn->write_ev = NULL;
		return false;
	}

	return true;
}

static bool nc_conn_write_disable(struct nc_conn *conn)
{
	if (!conn->write_ev)
		return true;

	event_del(conn->write_ev);
	event_free(conn->write_ev);

	conn->write_ev = NULL;

	return true;
}

static void nc_conn_evt_connected(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;

	if ((events & EV_WRITE) == 0) {
		fprintf(plog, "net: %s connection timeout\n", conn->addr_str);
		goto err_out;
	}

	int err = 0;
	socklen_t len = sizeof(err);

	/* check success of connect(2) */
	if ((getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) ||
	    (err != 0)) {
		fprintf(plog, "net: connect %s failed: %s\n",
			conn->addr_str, strerror(err));
		goto err_out;
	}

	if (debugging)
		fprintf(plog, "net: connected to %s\n", conn->addr_str);

	conn->connected = true;

	/* clear event used for watching connect(2) */
	event_free(conn->ev);
	conn->ev = NULL;

	/* build and send "version" message */
	cstring *msg_data = nc_version_build(conn);
	bool rc = nc_conn_send(conn, "version", msg_data->str, msg_data->len);
	cstr_free(msg_data, true);

	if (!rc) {
		fprintf(plog, "net: %s !conn_send\n", conn->addr_str);
		goto err_out;
	}

	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;

	if (!nc_conn_read_enable(conn)) {
		fprintf(plog, "net: %s read not enabled\n", conn->addr_str);
		goto err_out;
	}

	return;

err_out:
	nc_conn_kill(conn);
}

static void nc_conns_gc(struct net_child_info *nci, bool free_all)
{
	clist *dead = NULL;
	unsigned int n_gc = 0;

	/* build list of dead connections */
	unsigned int i;
	for (i = 0; i < nci->conns->len; i++) {
		struct nc_conn *conn = parr_idx(nci->conns, i);
		if (free_all || conn->dead)
			dead = clist_prepend(dead, conn);
	}

	/* remove and free dead connections */
	clist *tmp = dead;
	while (tmp) {
		struct nc_conn *conn = tmp->data;
		tmp = tmp->next;

		parr_remove(nci->conns, conn);
		nc_conn_free(conn);
		n_gc++;
	}

	clist_free(dead);

	if (debugging)
		fprintf(plog, "net: gc'd %u connections\n", n_gc);
}

static void nc_conns_open(struct net_child_info *nci)
{
	if (debugging)
		fprintf(plog, "net: open connections (have %zu, want %zu more)\n",
			nci->conns->len,
			NC_MAX_CONN - nci->conns->len);

	while ((bp_hashtab_size(nci->peers->map_addr) > 0) &&
	       (nci->conns->len < NC_MAX_CONN)) {

		/* delete peer from front of address list.  it will be
		 * re-added before writing peer file, if successful
		 */
		struct peer *peer = peerman_pop(nci->peers);

		struct nc_conn *conn = nc_conn_new(peer);
		conn->nci = nci;
		peer_free(peer);
		free(peer);

		if (debugging)
			fprintf(plog, "net: connecting to %s\n",
				conn->addr_str);

		/* are we already connected to this IP? */
		if (nc_conn_ip_active(nci, conn->peer.addr.ip)) {
			fprintf(plog, "net: already connected to %s\n",
				conn->addr_str);
			goto err_loop;
		}

		/* are we already connected to this network group? */
		if (nc_conn_group_active(nci, &conn->peer)) {
			fprintf(plog, "net: already grouped to %s\n",
				conn->addr_str);
			goto err_loop;
		}

		/* initiate non-blocking connect(2) */
		if (!nc_conn_start(conn)) {
			fprintf(plog, "net: failed to start connection to %s\n",
				conn->addr_str);
			goto err_loop;
		}

		/* add to our list of monitored event sources */
		conn->ev = event_new(nci->eb, conn->fd, EV_WRITE,
				     nc_conn_evt_connected, conn);
		if (!conn->ev) {
			fprintf(plog, "net: event_new failed on %s\n",
				conn->addr_str);
			goto err_loop;
		}

		struct timeval timeout = { net_conn_timeout, };
		if (event_add(conn->ev, &timeout) != 0) {
			fprintf(plog, "net: event_add failed on %s\n",
				conn->addr_str);
			goto err_loop;
		}

		/* add to our list of active connections */
		parr_add(nci->conns, conn);

		continue;

err_loop:
		nc_conn_kill(conn);
	}
}

static void nc_conns_process(struct net_child_info *nci)
{
	nc_conns_gc(nci, false);
	nc_conns_open(nci);
}

static bool parse_kvstr(const char *s, char **key, char **value)
{
	char *eql;

	eql = strchr(s, '=');
	if (eql) {
		unsigned int keylen = eql - s;
		*key = strndup(s, keylen);
		*value = strdup(s + keylen + 1);
	} else {
		*key = strdup(s);
		*value = strdup("");
	}

	/* blank keys forbidden; blank values permitted */
	if (!strlen(*key)) {
		free(*key);
		free(*value);
		*key = NULL;
		*value = NULL;
		return false;
	}

	return true;
}

static bool read_config_file(const char *cfg_fn)
{
	FILE *cfg = fopen(cfg_fn, "r");
	if (!cfg)
		return false;

	bool rc = false;

	char line[1024];
	while (fgets(line, sizeof(line), cfg) != NULL) {
		char *key, *value;

		if (line[0] == '#')
			continue;
		while (line[0] && (isspace(line[strlen(line) - 1])))
			line[strlen(line) - 1] = 0;

		if (!parse_kvstr(line, &key, &value))
			continue;

		bp_hashtab_put(settings, key, value);
	}

	rc = ferror(cfg) == 0;

	fclose(cfg);
	return rc;
}

static bool do_setting(const char *arg)
{
	char *key, *value;

	if (!parse_kvstr(arg, &key, &value))
		return false;

	bp_hashtab_put(settings, key, value);

	/*
	 * trigger special setting-specific behaviors
	 */

	if (!strcmp(key, "debug"))
		debugging = true;

	else if (!strcmp(key, "config") || !strcmp(key, "c"))
		return read_config_file(value);

	return true;
}

static bool preload_settings(void)
{
	unsigned int i;

	/* preload static settings */
	for (i = 0; i < ARRAY_SIZE(const_settings); i++)
		if (!do_setting(const_settings[i]))
			return false;

	return true;
}

static void chain_set(void)
{
	char *name = setting("chain");
	const struct chain_info *new_chain = chain_find(name);
	if (!new_chain) {
		fprintf(stderr, "chain-set: unknown chain '%s'\n", name);
		exit(1);
	}

	bu256_t new_genesis;
	if (!hex_bu256(&new_genesis, new_chain->genesis_hash)) {
		fprintf(stderr, "chain-set: invalid genesis hash %s\n",
			new_chain->genesis_hash);
		exit(1);
	}

	chain = new_chain;
	bu256_copy(&chain_genesis, &new_genesis);
}

static void init_log(void)
{
	char *log_fn = setting("log");
	if (!log_fn || !strcmp(log_fn, "-"))
		plog = stdout;
	else {
		plog = fopen(log_fn, "a");
		if (!plog) {
			perror(log_fn);
			exit(1);
		}
	}

	setvbuf(plog, NULL, _IONBF, BUFSIZ);
}

static void init_blkdb(void)
{
	if (!blkdb_init(&db, chain->netmagic, &chain_genesis)) {
		fprintf(plog, "blkdb init failed\n");
		exit(1);
	}

	char *blkdb_fn = setting("blkdb");
	if (!blkdb_fn)
		return;

	if ((access(blkdb_fn, F_OK) == 0) &&
	    !blkdb_read(&db, blkdb_fn)) {
		fprintf(plog, "blkdb read failed\n");
		exit(1);
	}

	db.fd = open(blkdb_fn,
		     O_WRONLY | O_APPEND | O_CREAT | O_LARGEFILE, 0666);
	if (db.fd < 0) {
		fprintf(plog, "blkdb file open failed: %s\n", strerror(errno));
		exit(1);
	}
}

static const char *genesis_bitcoin =
"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";
static const char *genesis_testnet =
"0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae180101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

static void init_block0(void)
{
	const char *genesis_hex = NULL;

	switch (chain->chain_id) {
	case CHAIN_BITCOIN:
		genesis_hex = genesis_bitcoin;
		break;
	case CHAIN_TESTNET3:
		genesis_hex = genesis_testnet;
		break;
	default:
		fprintf(plog, "unsupported chain.  add genesis block here!\n");
		exit(1);
		break;
	}

	size_t olen = 0;
	size_t genesis_rawlen = strlen(genesis_hex) / 2;
	char genesis_raw[genesis_rawlen];
	if (!decode_hex(genesis_raw, sizeof(genesis_raw), genesis_hex, &olen)) {
		fprintf(plog, "chain hex decode fail\n");
		exit(1);
	}

	cstring *msg0 = message_str(chain->netmagic, "block",
				    genesis_raw, genesis_rawlen);
	ssize_t bwritten = write(blocks_fd, msg0->str, msg0->len);
	if (bwritten != msg0->len) {
		fprintf(plog, "blocks write0 failed: %s\n", strerror(errno));
		exit(1);
	}
	cstr_free(msg0, true);

	off64_t fpos64 = lseek64(blocks_fd, 0, SEEK_SET);
	if (fpos64 == (off64_t)-1) {
		fprintf(plog, "blocks lseek0 failed: %s\n", strerror(errno));
		exit(1);
	}

	fprintf(plog, "blocks: genesis block written\n");
}

static void init_blocks(void)
{
	char *blocks_fn = setting("blocks");
	if (!blocks_fn)
		return;

	blocks_fd = open(blocks_fn, O_RDWR | O_CREAT | O_LARGEFILE, 0666);
	if (blocks_fd < 0) {
		fprintf(plog, "blocks file open failed: %s\n", strerror(errno));
		exit(1);
	}

	off64_t flen = lseek64(blocks_fd, 0, SEEK_END);
	if (flen == (off64_t)-1) {
		fprintf(plog, "blocks file lseek64 failed: %s\n", strerror(errno));
		exit(1);
	}

	if (flen == 0)
		init_block0();
}

static bool spend_tx(struct bp_utxo_set *uset, const struct bp_tx *tx,
		     unsigned int tx_idx, unsigned int height)
{
	bool is_coinbase = (tx_idx == 0);

	struct bp_utxo *coin;

	int64_t total_in = 0, total_out = 0;

	unsigned int i;

	/* verify and spend this transaction's inputs */
	if (!is_coinbase) {
		for (i = 0; i < tx->vin->len; i++) {
			struct bp_txin *txin;
			struct bp_txout *txout;

			txin = parr_idx(tx->vin, i);

			coin = bp_utxo_lookup(uset, &txin->prevout.hash);
			if (!coin || !coin->vout)
				return false;

			if (coin->is_coinbase &&
			    ((coin->height + COINBASE_MATURITY) > height))
				return false;

			txout = NULL;
			if (txin->prevout.n >= coin->vout->len)
				return false;
			txout = parr_idx(coin->vout, txin->prevout.n);
			total_in += txout->nValue;

			if (script_verf &&
			    !bp_verify_sig(coin, tx, i,
						/* SCRIPT_VERIFY_P2SH */ 0, 0))
				return false;

			if (!bp_utxo_spend(uset, &txin->prevout))
				return false;
		}
	}

	for (i = 0; i < tx->vout->len; i++) {
		struct bp_txout *txout;

		txout = parr_idx(tx->vout, i);
		total_out += txout->nValue;
	}

	if (!is_coinbase) {
		if (total_out > total_in)
			return false;
	}

	/* copy-and-convert a tx into a UTXO */
	coin = calloc(1, sizeof(*coin));
	bp_utxo_init(coin);

	if (!bp_utxo_from_tx(coin, tx, is_coinbase, height))
		return false;

	/* add unspent outputs to set */
	bp_utxo_set_add(uset, coin);

	return true;
}

static bool spend_block(struct bp_utxo_set *uset, const struct bp_block *block,
			unsigned int height)
{
	unsigned int i;

	for (i = 0; i < block->vtx->len; i++) {
		struct bp_tx *tx;

		tx = parr_idx(block->vtx, i);
		if (!spend_tx(uset, tx, i, height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &tx->sha256);
			fprintf(plog, "brd: spent_block tx fail %s\n", hexstr);
			return false;
		}
	}

	return true;
}

static bool process_block(const struct bp_block *block, int64_t fpos)
{
	struct blkinfo *bi = bi_new();
	bu256_copy(&bi->hash, &block->sha256);
	bp_block_copy_hdr(&bi->hdr, block);
	bi->n_file = 0;
	bi->n_pos = fpos;

	struct blkdb_reorg reorg;

	if (!blkdb_add(&db, bi, &reorg)) {
		fprintf(plog, "brd: blkdb add fail\n");
		goto err_out;
	}

	/* FIXME: support reorg */
	assert(reorg.conn == 1);
	assert(reorg.disconn == 0);

	/* if best chain, mark TX's as spent */
	if (bu256_equal(&db.best_chain->hash, &bi->hdr.sha256)) {
		if (!spend_block(&uset, block, bi->height)) {
			char hexstr[BU256_STRSZ];
			bu256_hex(hexstr, &bi->hdr.sha256);
			fprintf(plog,
				"brd: block spend fail %u %s\n",
				bi->height, hexstr);
			/* FIXME: bad record is now in blkdb */
			goto err_out;
		}
	}

	return true;

err_out:
	bi_free(bi);
	return false;
}

static bool read_block_msg(struct p2p_message *msg, int64_t fpos)
{
	/* unknown records are invalid */
	if (strncmp(msg->hdr.command, "block",
		    sizeof(msg->hdr.command)))
		return false;

	bool rc = false;

	struct bp_block block;
	bp_block_init(&block);

	struct const_buffer buf = { msg->data, msg->hdr.data_len };
	if (!deser_bp_block(&block, &buf)) {
		fprintf(plog, "brd: block deser fail\n");
		goto out;
	}
	bp_block_calc_sha256(&block);

	if (!bp_block_valid(&block)) {
		fprintf(plog, "brd: block not valid\n");
		goto out;
	}

	rc = process_block(&block, fpos);

out:
	bp_block_free(&block);
	return rc;
}

static void read_blocks(void)
{
	int fd = blocks_fd;

	struct p2p_message msg = {};
	bool read_ok = true;
	int64_t fpos = 0;
	while (fread_message(fd, &msg, &read_ok)) {
		if (memcmp(msg.hdr.netmagic, chain->netmagic, 4)) {
			fprintf(plog, "blocks file: invalid network magic\n");
			exit(1);
		}

		if (!read_block_msg(&msg, fpos))
			exit(1);

		fpos += P2P_HDR_SZ;
		fpos += msg.hdr.data_len;
	}

	if (!read_ok) {
		fprintf(plog, "blocks file: read failed\n");
		exit(1);
	}

	free(msg.data);
}

static void readprep_blocks_file(void)
{
	/* if no blk index, but blocks are present, read and index
	 * all block data (several gigabytes)
	 */
	if (blocks_fd >= 0) {
		if (db.fd < 0)
			read_blocks();
		else {
			/* TODO: verify that blocks file offsets are
			 * present in blkdb */

			if (lseek(blocks_fd, 0, SEEK_END) == (off_t)-1) {
				fprintf(plog, "blocks file: seek failed: %s\n",
					strerror(errno));
				exit(1);
			}
		}
	}
}

static void init_orphans(void)
{
	orphans = bp_hashtab_new_ext(bu256_hash, bu256_equal_,
				     (bp_freefunc) bu256_free, (bp_freefunc) buffer_free);
}

static bool have_orphan(const bu256_t *v)
{
	return bp_hashtab_get(orphans, v);
}

static bool add_orphan(const bu256_t *hash_in, struct const_buffer *buf_in)
{
	if (have_orphan(hash_in))
		return false;

	bu256_t *hash = bu256_new(hash_in);
	if (!hash) {
		fprintf(plog, "OOM\n");
		return false;
	}

	struct buffer *buf = buffer_copy(buf_in->p, buf_in->len);
	if (!buf) {
		bu256_free(hash);
		fprintf(plog, "OOM\n");
		return false;
	}

	bp_hashtab_put(orphans, hash, buf);
	
	return true;
}

static void init_peers(struct net_child_info *nci)
{
	/*
	 * read network peers
	 */
	struct peer_manager *peers;

	peers = peerman_read();
	if (!peers) {
		fprintf(plog, "net: initializing empty peer list\n");

		peers = peerman_seed(setting("no_dns") == NULL ? true : false);
		if (!peerman_write(peers)) {
			fprintf(plog, "net: failed to write peer list\n");
			exit(1);
		}
	}

	char *addnode = setting("addnode");
	if (addnode)
		peerman_addstr(peers, addnode);

	peerman_sort(peers);

	if (debugging)
		fprintf(plog, "net: have %u/%zu peers\n",
			bp_hashtab_size(peers->map_addr),
			clist_length(peers->addrlist));

	nci->peers = peers;
}

static void init_nci(struct net_child_info *nci)
{
	memset(nci, 0, sizeof(*nci));
	nci->read_fd = -1;
	nci->write_fd = -1;
	init_peers(nci);
	nci->conns = parr_new(NC_MAX_CONN, NULL);
	nci->eb = event_base_new();
}

static void init_daemon(struct net_child_info *nci)
{
	init_log();
	init_blkdb();
	bp_utxo_set_init(&uset);
	init_blocks();
	init_orphans();
	readprep_blocks_file();
	init_nci(nci);
}

static void run_daemon(struct net_child_info *nci)
{
	/* main loop */
	do {
		nc_conns_process(nci);
		event_base_dispatch(nci->eb);
	} while (daemon_running);
}

static void shutdown_nci(struct net_child_info *nci)
{
	peerman_free(nci->peers);
	nc_conns_gc(nci, true);
	assert(nci->conns->len == 0);
	parr_free(nci->conns, true);
	event_base_free(nci->eb);
}

static void shutdown_daemon(struct net_child_info *nci)
{
	bool rc = peerman_write(nci->peers);
	fprintf(plog, "net: %s %u/%zu peers\n",
		rc ? "wrote" : "failed to write",
		bp_hashtab_size(nci->peers->map_addr),
		clist_length(nci->peers->addrlist));

	if (plog != stdout && plog != stderr) {
		fclose(plog);
		plog = NULL;
	}

	if (setting("free")) {
		shutdown_nci(nci);
		bp_hashtab_unref(orphans);
		bp_hashtab_unref(settings);
		blkdb_free(&db);
		bp_utxo_set_free(&uset);
	}
}

static void term_signal(int signo)
{
	daemon_running = false;
	event_base_loopbreak(global_nci.eb);
}

int main (int argc, char *argv[])
{
	settings = bp_hashtab_new_ext(czstr_hash, czstr_equal,
				      free, free);

	if (!preload_settings())
		return 1;
	chain_set();

	RAND_bytes((unsigned char *)&instance_nonce, sizeof(instance_nonce));

	unsigned int arg;
	for (arg = 1; arg < argc; arg++) {
		const char *argstr = argv[arg];
		if (!do_setting(argstr))
			return 1;
	}

	/*
	 * properly capture TERM and other signals
	 */
	signal(SIGHUP, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGINT, term_signal);
	signal(SIGTERM, term_signal);

	init_daemon(&global_nci);
	run_daemon(&global_nci);

	fprintf(plog, "daemon exiting\n");

	shutdown_daemon(&global_nci);

	return 0;
}

