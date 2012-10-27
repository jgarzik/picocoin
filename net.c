
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <poll.h>
#include <glib.h>
#include <event.h>
#include "util.h"
#include "mbr.h"
#include "core.h"
#include "picocoin.h"

struct net_engine {
	bool		running;
	int		rx_pipefd[2];
	int		tx_pipefd[2];
	int		par_read;
	int		par_write;
	pid_t		child;
};

enum netcmds {
	NC_OK,
	NC_ERR,
	NC_TIMEOUT,
	NC_START,
	NC_STOP,
};

struct peer_manager {
	GList		*addrlist;	/* of struct bp_address */
	unsigned int	count;		/* # of peers in addrlist */
};

struct net_child_info {
	int			read_fd;
	int			write_fd;
	struct peer_manager	*peers;
	GPtrArray		*conns;
	struct event_base	*eb;
};

struct nc_conn {
	int			fd;
	struct bp_address	addr;
	bool			ipv4;
	bool			connected;
	struct event		*ev;
	struct net_child_info	*nci;

	struct p2p_message	msg;

	void			*msg_p;
	unsigned int		expected;
	bool			reading_hdr;
	unsigned char		hdrbuf[P2P_HDR_SZ];
};


enum {
	NC_MAX_CONN		= 8,
};

static void peerman_free(struct peer_manager *peers)
{
	if (!peers)
		return;
	
	g_list_free_full(peers->addrlist, g_free);

	free(peers);
}

static bool peerman_read_rec(struct peer_manager *peers,struct p2p_message *msg)
{
	if (strncmp(msg->hdr.command, "CAddress", sizeof(msg->hdr.command)) ||
	    (msg->hdr.data_len != sizeof(struct bp_address)))
		return false;

	struct buffer buf = { msg->data, msg->hdr.data_len };
	struct bp_address *addr;

	addr = calloc(1, sizeof(*addr));

	if (!deser_bp_addr(CADDR_TIME_VERSION, addr, &buf)) {
		free(addr);
		return false;
	}

	peers->addrlist = g_list_prepend(peers->addrlist, addr);
	peers->count++;

	return true;
}

static struct peer_manager *peerman_read(void)
{
	char *filename = setting("peers");
	if (!filename)
		return NULL;

	void *data = NULL;
	size_t data_len = 0;

	if (!bu_read_file(filename, &data, &data_len, 100 * 1024 * 1024))
		return NULL;

	struct peer_manager *peers;

	peers = calloc(1, sizeof(*peers));

	struct buffer buf = { data, data_len };
	struct mbuf_reader mbr;

	mbr_init(&mbr, &buf);

	while (mbr_read(&mbr)) {
		if (!peerman_read_rec(peers, &mbr.msg)) {
			mbr.error = true;
			break;
		}
	}

	if (mbr.error) {
		peerman_free(peers);
		peers = NULL;
	}

	mbr_free(&mbr);
	free(data);

	return peers;
}

static struct peer_manager *peerman_seed(void)
{
	struct peer_manager *peers;

	peers = calloc(1, sizeof(*peers));
	if (!peers)
		return NULL;
	
	peers->addrlist = bu_dns_seed_addrs();
	peers->count = g_list_length(peers->addrlist);
	
	return peers;
}

static GString *ser_peerman(struct peer_manager *peers)
{
	GString *s = g_string_sized_new(
		peers->count * (24 + sizeof(struct bp_address)));

	GList *tmp = peers->addrlist;

	while (tmp) {
		struct bp_address *addr;

		addr = tmp->data;
		tmp = tmp->next;

		GString *msg_data = g_string_sized_new(sizeof(struct bp_address));
		ser_bp_addr(msg_data, CADDR_TIME_VERSION, addr);

		GString *rec = message_str(chain->netmagic, "CAddress",
					   msg_data->str, msg_data->len);

		g_string_append_len(s, rec->str, rec->len);

		g_string_free(rec, TRUE);
		g_string_free(msg_data, TRUE);
	}

	return s;
}

static bool peerman_write(struct peer_manager *peers)
{
	char *filename = setting("peers");
	if (!filename)
		return false;

	GString *data = ser_peerman(peers);

	bool rc = bu_write_file(filename, data->str, data->len);

	g_string_free(data, TRUE);

	return rc;
}

static struct bp_address *peerman_pop(struct peer_manager *peers)
{
	struct bp_address *addr;
	GList *tmp;

	tmp = peers->addrlist;
	if (!tmp)
		return NULL;

	addr = tmp->data;

	peers->addrlist = g_list_delete_link(tmp, tmp);
	peers->count--;

	return addr;
}

static void pipwr(int fd, const void *buf, size_t len)
{
	while (len > 0) {
		ssize_t wrc;

		wrc = write(fd, buf, len);
		if (wrc < 0) {
			perror("pipe write");
			return;
		}

		buf += wrc;
		len -= wrc;
	}
}

static void sendcmd(int fd, enum netcmds nc)
{
	uint8_t v = nc;
	pipwr(fd, &v, 1);
}

static enum netcmds readcmd(int fd, int timeout_secs)
{
	struct pollfd pfd = { fd, POLLIN };
	int prc = poll(&pfd, 1, timeout_secs ? timeout_secs * 1000 : -1);
	if (prc < 0) {
		perror("pipe poll");
		return NC_ERR;
	}
	if (prc == 0)
		return NC_TIMEOUT;
	
	uint8_t v;
	ssize_t rrc = read(fd, &v, 1);
	if (rrc < 0) {
		perror("pipe read");
		return NC_ERR;
	}
	if (rrc != 1)
		return NC_ERR;

	return v;
}

static bool nc_conn_message(struct nc_conn *conn)
{
	/* TODO: we have a valid incoming message... do something with it */

	return false; /* FIXME */
}

static bool nc_conn_ip_active(struct net_child_info *nci,
			      struct nc_conn *conn_new)
{
	unsigned int i;
	for (i = 0; i < nci->conns->len; i++) {
		struct nc_conn *conn;

		conn = g_ptr_array_index(nci->conns, i);
		if (!memcmp(conn->addr.ip, conn_new->addr.ip, 16))
			return true;
	}
	
	return false;
}

static struct nc_conn *nc_conn_new(const struct bp_address *addr_in)
{
	struct nc_conn *conn;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;

	conn->fd = -1;

	if (addr_in)
		memcpy(&conn->addr, addr_in, sizeof(*addr_in));

	return conn;
}

static void nc_conn_free(struct nc_conn *conn)
{
	if (!conn)
		return;

	if (conn->ev) {
		event_del(conn->ev);
		event_free(conn->ev);
	}

	if (conn->fd >= 0)
		close(conn->fd);

	free(conn->msg.data);
	
	free(conn);
}

static bool nc_conn_start(struct nc_conn *conn)
{
	/* create socket */
	conn->ipv4 = is_ipv4_mapped(conn->addr.ip);
	conn->fd = socket(conn->ipv4 ? AF_INET : AF_INET6,
			  SOCK_STREAM, IPPROTO_TCP);
	if (conn->fd < 0)
		return false;

	/* set non-blocking */
	int flags = fcntl(conn->fd, F_GETFL, 0);
	if ((flags < 0) ||
	    (fcntl(conn->fd, F_SETFL, flags | O_NONBLOCK) < 0))
		return false;

	struct sockaddr *saddr;
	struct sockaddr_in6 saddr6;
	struct sockaddr_in saddr4;
	socklen_t saddr_len;

	/* fill out connect(2) address */
	if (conn->ipv4) {
		memset(&saddr4, 0, sizeof(saddr4));
		saddr4.sin_family = AF_INET;
		memcpy(&saddr4.sin_addr.s_addr,
		       &conn->addr.ip[12], 4);
		saddr4.sin_port = htons(conn->addr.port);

		saddr = (struct sockaddr *) &saddr4;
		saddr_len = sizeof(saddr4);
	} else {
		memset(&saddr6, 0, sizeof(saddr6));
		saddr6.sin6_family = AF_INET6;
		memcpy(&saddr6.sin6_addr.s6_addr,
		       &conn->addr.ip[0], 16);
		saddr6.sin6_port = htons(conn->addr.port);

		saddr = (struct sockaddr *) &saddr6;
		saddr_len = sizeof(saddr6);
	}

	/* initiate TCP connection */
	if (connect(conn->fd, saddr, saddr_len) < 0)
		return false;

	return true;
}

static void nc_conn_got_header(struct nc_conn *conn)
{
	parse_message_hdr(&conn->msg.hdr, conn->hdrbuf);

	unsigned int data_len = conn->msg.hdr.data_len;
	if (data_len > (16 * 1024 * 1024))
		goto err_out;

	conn->msg.data = malloc(data_len);

	/* switch to read-body state */
	conn->msg_p = conn->msg.data;
	conn->expected = data_len;
	conn->reading_hdr = false;

	return;

err_out:
	nc_conn_free(conn);
}

static void nc_conn_got_msg(struct nc_conn *conn)
{
	if (!message_valid(&conn->msg))
		goto err_out;

	if (!nc_conn_message(conn))
		goto err_out;

	free(conn->msg.data);
	conn->msg.data = NULL;

	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;

	return;

err_out:
	nc_conn_free(conn);
}

static void nc_conn_evt(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;

	ssize_t rrc = read(fd, conn->msg_p, conn->expected);
	if (rrc <= 0) {
		nc_conn_free(conn);
		return;
	}

	conn->msg_p += rrc;
	conn->expected -= rrc;

	if (conn->expected == 0) {
		if (conn->reading_hdr)
			nc_conn_got_header(conn);
		else	
			nc_conn_got_msg(conn);
	}
}

static void nc_conn_evt_connected(int fd, short events, void *priv)
{
	struct nc_conn *conn = priv;

	int err = 0;
	socklen_t len = sizeof(err);

	if ((getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) ||
	    (err != 0))
		goto err_out;

	conn->connected = true;

	event_free(conn->ev);

	// FIXME: send initial network protocol greetings etc.

	/* switch to read-header state */
	conn->msg_p = conn->hdrbuf;
	conn->expected = P2P_HDR_SZ;
	conn->reading_hdr = true;

	conn->ev = event_new(conn->nci->eb, conn->fd, EV_READ | EV_PERSIST, 
			     nc_conn_evt, conn);
	if (!conn->ev)
		goto err_out;

	if (event_add(conn->ev, NULL) != 0)
		goto err_out;

	return;

err_out:
	nc_conn_free(conn);
}

static void nc_conns_open(struct net_child_info *nci)
{
	while (nci->peers->count && (nci->conns->len < NC_MAX_CONN)) {

		/* delete peer from front of address list.  it will be
		 * re-added before writing peer file, if successful
		 */
		struct bp_address *addr = peerman_pop(nci->peers);

		struct nc_conn *conn = nc_conn_new(addr);
		conn->nci = nci;
		free(addr);

		/* are we already connected to this IP? */
		if (nc_conn_ip_active(nci, conn))
			goto err_loop;

		/* initiate non-blocking connect(2) */
		if (!nc_conn_start(conn))
			goto err_loop;

		/* add to our list of monitored event sources */
		conn->ev = event_new(nci->eb, conn->fd, EV_WRITE,
				     nc_conn_evt_connected, conn);
		if (!conn->ev)
			goto err_loop;

		struct timeval timeout = { 60, };
		if (event_add(conn->ev, &timeout) != 0)
			goto err_loop;

		/* add to our list of active connections */
		g_ptr_array_add(nci->conns, conn);

		continue;

err_loop:
		nc_conn_free(conn);
	}
}

static void nc_pipe_evt(int fd, short events, void *priv)
{
	struct net_child_info *nci = priv;

	enum netcmds nc = readcmd(nci->read_fd, 0);
	switch (nc) {

	case NC_START:
		sendcmd(nci->write_fd, NC_OK);
		break;

	case NC_STOP:
		sendcmd(nci->write_fd, NC_OK);
		event_base_loopbreak(nci->eb);
		break;

	default:
		exit(1);
	}
}

static void network_child(int read_fd, int write_fd)
{
	struct peer_manager *peers;

	peers = peerman_read();
	if (!peers) {
		peers = peerman_seed();
		peerman_write(peers);
	}

	struct net_child_info nci = { read_fd, write_fd, peers };
	nci.conns = g_ptr_array_sized_new(8);

	struct event *pipe_evt;

	nci.eb = event_base_new();
	pipe_evt = event_new(nci.eb, read_fd, EV_READ | EV_PERSIST,
			     nc_pipe_evt, &nci);
	event_add(pipe_evt, NULL);

	nc_conns_open(&nci);		/* start opening P2P connections */

	event_base_dispatch(nci.eb);	/* main loop */

	peerman_write(peers);
	exit(0);
}

struct net_engine *neteng_new(void)
{
	struct net_engine *neteng;

	neteng = calloc(1, sizeof(*neteng));

	neteng->rx_pipefd[0] = -1;
	neteng->rx_pipefd[1] = -1;
	neteng->tx_pipefd[0] = -1;
	neteng->tx_pipefd[1] = -1;

	return neteng;
}

static void neteng_child_kill(pid_t child)
{
	kill(child, SIGTERM);
	sleep(1);
	waitpid(child, NULL, WNOHANG);
}

static bool neteng_cmd_exec(pid_t child, int read_fd, int write_fd,
			    enum netcmds nc)
{
	sendcmd(write_fd, nc);

	enum netcmds ncr = readcmd(read_fd, 60);
	if (ncr != NC_OK)
		return false;
	
	return true;
}

bool neteng_start(struct net_engine *neteng)
{
	if (neteng->running)
		return false;

	if (pipe(neteng->rx_pipefd) < 0)
		return false;
	if (pipe(neteng->tx_pipefd) < 0)
		goto err_out_rxfd;

	neteng->child = fork();
	if (neteng->child == -1)
		goto err_out_txfd;

	/* child execution path continues here */
	if (neteng->child == 0) {
		network_child(neteng->tx_pipefd[0], neteng->rx_pipefd[1]);
		exit(0);
	}

	/* otherwise, we are the parent */

	int par_read = neteng->par_read = neteng->rx_pipefd[0];
	int par_write = neteng->par_write = neteng->tx_pipefd[1];

	if (!neteng_cmd_exec(neteng->child, par_read, par_write, NC_START))
		goto err_out_child;

	neteng->running = true;
	return true;

err_out_child:
	neteng_child_kill(neteng->child);
err_out_txfd:
	close(neteng->tx_pipefd[0]);
	close(neteng->tx_pipefd[1]);
err_out_rxfd:
	close(neteng->rx_pipefd[0]);
	close(neteng->rx_pipefd[1]);
	neteng->rx_pipefd[0] = -1;
	neteng->rx_pipefd[1] = -1;
	neteng->tx_pipefd[0] = -1;
	neteng->tx_pipefd[1] = -1;
	return false;
}

void neteng_stop(struct net_engine *neteng)
{
	if (!neteng->running)
		return;

	if (!neteng_cmd_exec(neteng->child, neteng->par_read,
			     neteng->par_write, NC_STOP))
		kill(neteng->child, SIGTERM);
	sleep(1);
	waitpid(neteng->child, NULL, WNOHANG);

	close(neteng->tx_pipefd[0]);
	close(neteng->tx_pipefd[1]);
	close(neteng->rx_pipefd[0]);
	close(neteng->rx_pipefd[1]);
	neteng->rx_pipefd[0] = -1;
	neteng->rx_pipefd[1] = -1;
	neteng->tx_pipefd[0] = -1;
	neteng->tx_pipefd[1] = -1;

	neteng->running = false;
}

void neteng_free(struct net_engine *neteng)
{
	neteng_stop(neteng);
	
	memset(neteng, 0, sizeof(*neteng));
	free(neteng);
}

static struct net_engine *neteng_new_start(void)
{
	struct net_engine *neteng;

	neteng = neteng_new();
	if (!neteng) {
		fprintf(stderr, "neteng new fail\n");
		exit(1);
	}

	if (!neteng_start(neteng)) {
		fprintf(stderr, "failed to start engine\n");
		exit(1);
	}

	return neteng;
}

void network_sync(void)
{
	struct net_engine *neteng = neteng_new_start();

	neteng_free(neteng);
}

