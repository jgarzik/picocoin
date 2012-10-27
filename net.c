
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <signal.h>
#include <poll.h>

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

static void network_parent(pid_t child, int read_fd, int write_fd)
{
	sendcmd(write_fd, NC_START);

	enum netcmds nc = readcmd(read_fd, 300);
	if (nc != NC_OK)
		goto err_out;
	
	sendcmd(write_fd, NC_STOP);

	nc = readcmd(read_fd, 300);
	if (nc != NC_OK)
		goto err_out;
	
	sleep(1);
	waitpid(child, NULL, WNOHANG);

	return;

err_out:
	fprintf(stderr, "network parent: error seen, killing child\n");
	kill(child, SIGTERM);
	sleep(1);
	waitpid(child, NULL, WNOHANG);
}

void network_sync(void)
{
	int tx_pipefd[2], rx_pipefd[2];
	pid_t child;

	if (pipe(tx_pipefd) < 0 || pipe(rx_pipefd) < 0) {
		perror("pipe");
		exit(1);
	}

	child = fork();
	if (child == -1) {
		perror("fork");
		exit(1);
	}

	if (child == 0)
		network_child(tx_pipefd[0], rx_pipefd[1]);
	else
		network_parent(child, rx_pipefd[0], tx_pipefd[1]);

	close(rx_pipefd[0]);
	close(rx_pipefd[1]);
	close(tx_pipefd[0]);
	close(tx_pipefd[1]);
}

