
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
	while (1) {
		enum netcmds nc = readcmd(read_fd, 0);
		switch (nc) {

		case NC_START:
			sendcmd(write_fd, NC_OK);
			break;

		case NC_STOP:
			sendcmd(write_fd, NC_OK);
			exit(0);

		default:
			/* do nothing */
			break;
		}
	}
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

void network_sync(void)
{
	struct net_engine *neteng;

	neteng = neteng_new();
	if (!neteng) {
		fprintf(stderr, "netsync: neteng new fail\n");
		exit(1);
	}

	if (!neteng_start(neteng)) {
		fprintf(stderr, "netsync: failed to start engine\n");
		exit(1);
	}

	neteng_stop(neteng);
	neteng_free(neteng);
}

