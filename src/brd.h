#ifndef __BRD_H__
#define __BRD_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/buint.h>                // for bu256_t
#include <ccoin/hashtab.h>              // for bp_hashtab_get

#include <stdbool.h>                    // for bool
#include <stdint.h>                     // for uint64_t

/* main.c */
extern struct bp_hashtab *settings;
extern const struct chain_info *chain;
extern bu256_t chain_genesis;
extern uint64_t instance_nonce;
extern bool debugging;

static inline char *setting(const char *key)
{
	return bp_hashtab_get(settings, key);
}

#endif /* __BRD_H__ */
