#ifndef __PICOCOIN_H__
#define __PICOCOIN_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ccoin/coredefs.h>
#include <ccoin/buint.h>
#include <ccoin/core.h>
#include <ccoin/hashtab.h>

struct wallet;

enum {
	PROTO_VERSION		= 60002,
};

/* main.c */
extern struct bp_hashtab *settings;
extern struct wallet *cur_wallet;
extern const struct chain_info *chain;
extern bu256_t chain_genesis;
extern uint64_t instance_nonce;
extern bool debugging;

/* net.c */
extern void network_sync(void);

/* aes.c */
extern cstring *read_aes_file(const char *filename, void *key, size_t key_len,
			      size_t max_file_len);
extern bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len);

static inline char *setting(const char *key)
{
	return bp_hashtab_get(settings, key);
}

#endif /* __PICOCOIN_H__ */
