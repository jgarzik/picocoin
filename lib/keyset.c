/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
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

	ks->pub = bp_hashtab_new_ext(buffer_hash, buffer_equal,
				     (bp_freefunc) buffer_free, NULL);
	ks->pubhash = bp_hashtab_new_ext(buffer_hash, buffer_equal,
					 (bp_freefunc) buffer_free, NULL);
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

	bp_hashtab_put(ks->pub, buf_pk, buf_pk);
	bp_hashtab_put(ks->pubhash, buf_pkhash, buf_pkhash);

	return true;
}

bool bpks_lookup(const struct bp_keyset *ks, const void *data, size_t data_len,
		 bool is_pubkeyhash)
{
	struct const_buffer buf = { data, data_len };
	struct bp_hashtab *ht;

	if (is_pubkeyhash)
		ht = ks->pubhash;
	else
		ht = ks->pub;

	return bp_hashtab_get_ext(ht, &buf, NULL, NULL);
}

void bpks_free(struct bp_keyset *ks)
{
	bp_hashtab_unref(ks->pub);
	bp_hashtab_unref(ks->pubhash);
}

