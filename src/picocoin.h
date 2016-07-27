#ifndef __PICOCOIN_H__
#define __PICOCOIN_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/buint.h>                // for bu256_t
#include <ccoin/cstr.h>                 // for cstring
#include <ccoin/hashtab.h>              // for bp_hashtab_get

#include <stddef.h>                     // for size_t
#include <stdint.h>                     // for uint64_t


struct wallet;

/* main.c */
extern struct bp_hashtab *settings;
extern const struct chain_info *chain;
extern bu256_t chain_genesis;
extern uint64_t instance_nonce;
extern struct wallet *cur_wallet;

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
