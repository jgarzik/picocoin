#ifndef __BRD_H__
#define __BRD_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

enum {
	PROTO_VERSION		= 60002,
};

/* main.c */
extern GHashTable *settings;
extern const struct chain_info *chain;
extern bu256_t chain_genesis;
extern uint64_t instance_nonce;
extern bool debugging;

static inline char *setting(const char *key)
{
	return g_hash_table_lookup(settings, key);
}

#endif /* __BRD_H__ */
