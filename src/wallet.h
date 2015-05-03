#ifndef __PICOCOIN_WALLET_H__
#define __PICOCOIN_WALLET_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

struct wallet {
	uint32_t	version;
	unsigned char	netmagic[4];

	GPtrArray	*keys;
};

extern void wallet_new_address(void);
extern void wallet_create(void);
extern void wallet_info(void);
extern void wallet_dump(void);
extern void wallet_addresses(void);
extern void cur_wallet_free(void);

#define wallet_for_each_key_numbered(_wlt, _key, _num)			\
	(_num) = 0;							\
	for ((_key) = g_ptr_array_index((_wlt)->keys, (_num));		\
		(_wlt)->keys && (_num) < (_wlt)->keys->len;		\
		(_key) = g_ptr_array_index((_wlt)->keys, ++(_num)))

#define wallet_for_each_key(_wlt, _key)				\
	unsigned int ___i;					\
	wallet_for_each_key_numbered(_wlt, _key, ___i)


#endif /* __PICOCOIN_WALLET_H__ */
