#ifndef __LIBCCOIN_COREDEFS_H__
#define __LIBCCOIN_COREDEFS_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifdef __cplusplus
extern "C" {
#endif

enum {
	BIP0031_VERSION		= 60000,
	CADDR_TIME_VERSION	= 31402,

	MIN_PROTO_VERSION	= 209,

	MAX_BLOCK_SIZE		= 1000000,

	COINBASE_MATURITY	= 100,
};

enum {
	COIN			= 100000000LL,
};

enum bp_address_type {
	PUBKEY_ADDRESS = 0,
	SCRIPT_ADDRESS = 5,
	PRIVKEY_ADDRESS = 128,
	PUBKEY_ADDRESS_TEST = 111,
	SCRIPT_ADDRESS_TEST = 196,
	PRIVKEY_ADDRESS_TEST = 239,
};

enum chains {
	CHAIN_BITCOIN,
	CHAIN_TESTNET3,

	CHAIN_LAST = CHAIN_TESTNET3
};

struct chain_info {
	enum chains		chain_id;
	const char		*name;		/* "bitcoin", "testnet3" */

	unsigned char		addr_pubkey;
	unsigned char		addr_script;

	unsigned char		netmagic[4];
	const char		*genesis_hash;	/* hex string */
};

extern const struct chain_info chain_metadata[];
extern const struct chain_info *chain_find(const char *name);
extern const struct chain_info *chain_find_by_netmagic(unsigned char netmagic[4]);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_COREDEFS_H__ */
