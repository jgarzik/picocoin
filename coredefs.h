#ifndef __LIBCCOIN_COREDEFS_H__
#define __LIBCCOIN_COREDEFS_H__

enum {
	CADDR_TIME_VERSION	= 31402
};

enum chains {
	CHAIN_BITCOIN,
	CHAIN_TESTNET3,

	CHAIN_LAST = CHAIN_TESTNET3
};

struct chain_info {
	enum chains		chain_id;
	const char		*name;		/* "bitcoin", "testnet3" */
	unsigned char		netmagic[4];
	const char		*genesis_hash;	/* hex string */
};

extern const struct chain_info chain_metadata[];
extern const struct chain_info *chain_find(const char *name);

#endif /* __LIBCCOIN_COREDEFS_H__ */
