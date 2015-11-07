#ifndef __LIBCCOIN_WALLET_H__
#define __LIBCCOIN_WALLET_H__
/* Copyright 2012 exMULTI, Inc.
 * Copyright 2015 Josh Cartwright <joshc@eso.teric.us>
 *
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <ccoin/cstr.h>
#include <ccoin/parr.h>

#ifdef __cplusplus
extern "C" {
#endif

struct chain_info;

struct wallet {
	uint32_t		version;
	const struct chain_info	*chain;

	parr			*keys;
};

struct const_buffer;

extern bool wallet_init(struct wallet *wlt, const struct chain_info *chain);
extern void wallet_free(struct wallet *wlt);
extern cstring *wallet_new_address(struct wallet *wlt);
extern cstring *ser_wallet(const struct wallet *wlt);
extern bool deser_wallet(struct wallet *wlt, struct const_buffer *buf);

#define wallet_for_each_key_numbered(_wlt, _key, _num)			\
	(_num) = 0;							\
	for ((_key) = parr_idx((_wlt)->keys, (_num));		\
		(_wlt)->keys && (_num) < (_wlt)->keys->len;		\
		(_key) = parr_idx((_wlt)->keys, ++(_num)))

#define wallet_for_each_key(_wlt, _key)				\
	unsigned int ___i;					\
	wallet_for_each_key_numbered(_wlt, _key, ___i)

#ifdef __cplusplus
}
#endif

#endif
