#ifndef __PICOCOIN_H__
#define __PICOCOIN_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <glib.h>
#include <openssl/bn.h>
#include "coredefs.h"

struct wallet;

enum {
	PROTO_VERSION		= 60002,
};

/* main.c */
extern GHashTable *settings;
extern struct wallet *cur_wallet;
extern const struct chain_info *chain;
extern uint64_t instance_nonce;

/* net.c */
extern void network_sync(void);

/* aes.c */
extern GString *read_aes_file(const char *filename, void *key, size_t key_len,
			      size_t max_file_len);
extern bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len);

static inline char *setting(const char *key)
{
	return g_hash_table_lookup(settings, key);
}

#endif /* __PICOCOIN_H__ */
