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
extern time_t wallet_oldest_key_time(void);

/* check if there is a key in wallet (bu_Hash160 comp. against buf) */
extern bool wallet_lookup_pubkey(const void *data, size_t data_len);
#endif /* __PICOCOIN_WALLET_H__ */
