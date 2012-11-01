
#include "picocoin-config.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/ripemd.h>
#include <ccoin/key.h>
#include <ccoin/buffer.h>
#include <ccoin/util.h>

void bpks_init(struct bp_keyset *ks)
{
	memset(ks, 0, sizeof(*ks));

	ks->pub = g_hash_table_new_full(buffer_hash, buffer_equal,
					(GDestroyNotify) buffer_free, NULL);
	ks->pubhash = g_hash_table_new_full(buffer_hash, buffer_equal,
					(GDestroyNotify) buffer_free, NULL);
}

bool bpks_add(struct bp_keyset *ks, struct bp_key *key)
{
	void *pubkey = NULL;
	size_t pk_len = 0;

	if (!bp_pubkey_get(key, &pubkey, &pk_len))
		return false;

	struct buffer *buf_pk = malloc(sizeof(struct buffer));
	buf_pk->p = pubkey;
	buf_pk->len = pk_len;

	unsigned char md160[RIPEMD160_DIGEST_LENGTH];
	bu_Hash160(md160, pubkey, pk_len);

	struct buffer *buf_pkhash = buffer_copy(md160, RIPEMD160_DIGEST_LENGTH);

	g_hash_table_replace(ks->pub, buf_pk, buf_pk);
	g_hash_table_replace(ks->pubhash, buf_pkhash, buf_pkhash);

	return true;
}

bool bpks_lookup(struct bp_keyset *ks, const void *data, size_t data_len,
		 bool is_pubkeyhash)
{
	struct const_buffer buf = { data, data_len };
	GHashTable *ht;

	if (is_pubkeyhash)
		ht = ks->pubhash;
	else
		ht = ks->pub;

	return g_hash_table_lookup_extended(ht, &buf, NULL, NULL);
}

void bpks_free(struct bp_keyset *ks)
{
	g_hash_table_unref(ks->pub);
	g_hash_table_unref(ks->pubhash);
}

