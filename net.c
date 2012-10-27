
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>
#include <glib.h>
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

static void network_child(int read_fd, int write_fd)
{
	struct peer_manager *peers;

	peers = peerman_read();
	if (!peers) {
		peers = peerman_seed();
		peerman_write(peers);
	}

	while (1) {
		enum netcmds nc = readcmd(read_fd, 0);
		switch (nc) {

		case NC_START:
			sendcmd(write_fd, NC_OK);
			break;

		case NC_STOP:
			sendcmd(write_fd, NC_OK);
			goto out;

		default:
			/* do nothing */
			break;
		}
	}

out:
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

