#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ccoin/coredefs.h>
#include <ccoin/message.h>
#include <ccoin/mbr.h>
#include "libtest.h"

static void runtest(bool use_testnet, const char *blocks_fn)
{
	const struct chain_info *chain =
		&chain_metadata[use_testnet ? CHAIN_TESTNET3 : CHAIN_BITCOIN];

	fprintf(stderr, "chain-verf: validating %s chainfile %s\n",
		use_testnet ? "testnet3" : "mainnet",
		blocks_fn);

	int fd = open(blocks_fn, O_RDONLY);
	if (fd < 0) {
		perror(blocks_fn);
		assert(fd >= 0);
	}

#if _XOPEN_SOURCE >= 600 || _POSIX_C_SOURCE >= 200112L
	posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

	struct p2p_message msg = {};
	bool read_ok = true;
	while (fread_message(fd, &msg, &read_ok)) {
		// TODO
		(void) chain;
	}

	assert(read_ok == true);

	close(fd);
	free(msg.data);
}

int main (int argc, char *argv[])
{
	char *fn;
	unsigned int verfd = 0;

	fn = getenv("TEST_TESTNET3_VERF");
	if (fn) {
		verfd++;
		runtest(true, fn);
	}

	fn = getenv("TEST_MAINNET_VERF");
	if (fn) {
		verfd++;
		runtest(false, fn);
	}

	if (!verfd) {
		fprintf(stderr,
	"chain-verf: Skipping lengthy, extended chain verification test.\n"
	"chain-verf: Set TEST_TESTNET3_VERF and/or TEST_MAINNET_VERF to a\n"
	"chain-verf: valid pynode blocks.dat file, to enable.\n"
	"chain-verf: (a linear sequence of P2P \"block\" messages)\n"
			);
		return 77;
	}
	
	return 0;
}
