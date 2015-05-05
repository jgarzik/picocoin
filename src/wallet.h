#ifndef __PICOCOIN_WALLET_H__
#define __PICOCOIN_WALLET_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <ccoin/parr.h>

struct chain_info;

struct wallet {
	uint32_t		version;
	const struct chain_info	*chain;

	parr			*keys;
};

extern struct wallet *wallet_new(const struct chain_info *chain);
extern void wallet_free(struct wallet *wlt);

extern void cur_wallet_new_address(void);
extern void cur_wallet_create(void);
extern void cur_wallet_info(void);
extern void cur_wallet_dump(void);
extern void cur_wallet_addresses(void);
extern void cur_wallet_free(void);

#define wallet_for_each_key_numbered(_wlt, _key, _num)			\
	(_num) = 0;							\
	for ((_key) = parr_idx((_wlt)->keys, (_num));		\
		(_wlt)->keys && (_num) < (_wlt)->keys->len;		\
		(_key) = parr_idx((_wlt)->keys, ++(_num)))

#define wallet_for_each_key(_wlt, _key)				\
	unsigned int ___i;					\
	wallet_for_each_key_numbered(_wlt, _key, ___i)


#endif /* __PICOCOIN_WALLET_H__ */
