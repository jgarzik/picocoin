/* Copyright 2016 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <assert.h>
#include <ccoin/buint.h>
#include <ccoin/checkpoints.h>
#include <ccoin/log.h>
#include "libtest.h"

static void test_checkpoints(void)
{
	bool rc;
	const char *hexstr;
	bu256_t tmp;

	hexstr = "0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d";
	rc = hex_bu256(&tmp, hexstr);
	assert(rc == true);

	// in list; pass
	rc = bp_ckpt_block(CHAIN_BITCOIN, 11111, &tmp);
	assert(rc == true);

	// not in list; pass
	rc = bp_ckpt_block(CHAIN_BITCOIN, 11112, &tmp);
	assert(rc == true);

	hexstr = "0x11111111111111111111111111111111111111111111192559f542fdb26e7c1d";
	rc = hex_bu256(&tmp, hexstr);
	assert(rc == true);

	// in list, mismatch hash; fail
	rc = bp_ckpt_block(CHAIN_BITCOIN, 11111, &tmp);
	assert(rc == false);

	assert(bp_ckpt_last(CHAIN_BITCOIN) == 193000);
	assert(bp_ckpt_last(CHAIN_TESTNET3) == 546);
}

static void test_log(void)
{
	char time_buf[32];
	char *p = str_timenow(time_buf);
	assert(p == &time_buf[0]);
}

int main (int argc, char *argv[])
{
	test_checkpoints();
	test_log();
	return 0;
}
