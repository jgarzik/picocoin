#ifndef __LIBCCOIN_KEY_H__
#define __LIBCCOIN_KEY_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <glib.h>
#include <openssl/ec.h>
#include <ccoin/buint.h>

struct bp_key {
	EC_KEY		*k;
};

extern bool bp_key_init(struct bp_key *key);
extern void bp_key_free(struct bp_key *key);
extern bool bp_key_generate(struct bp_key *key);
extern bool bp_privkey_set(struct bp_key *key, const void *privkey, size_t pk_len);
extern bool bp_pubkey_set(struct bp_key *key, const void *pubkey, size_t pk_len);
extern bool bp_key_secret_set(struct bp_key *key, const void *privkey_, size_t pk_len);
extern bool bp_privkey_get(struct bp_key *key, void **privkey, size_t *pk_len);
extern bool bp_pubkey_get(struct bp_key *key, void **pubkey, size_t *pk_len);
extern bool bp_key_secret_get(void *p, size_t len, const struct bp_key *key);
extern bool bp_sign(struct bp_key *key, const void *data, size_t data_len,
	     void **sig_, size_t *sig_len_);
extern bool bp_verify(struct bp_key *key, const void *data, size_t data_len,
	       const void *sig, size_t sig_len);

struct bp_keyset {
	GHashTable	*pub;
	GHashTable	*pubhash;
};

extern void bpks_init(struct bp_keyset *ks);
extern bool bpks_add(struct bp_keyset *ks, struct bp_key *key);
extern bool bpks_lookup(const struct bp_keyset *ks, const void *data, size_t data_len,
		 bool is_pubkeyhash);
extern void bpks_free(struct bp_keyset *ks);

struct bp_keystore {
	GHashTable	*keys;
};

extern void bkeys_init(struct bp_keystore *ks);
extern void bkeys_free(struct bp_keystore *ks);
extern bool bkeys_add(struct bp_keystore *ks, struct bp_key *key);
extern bool bkeys_privkey_get(struct bp_keystore *ks, const bu160_t *key_id,
		      struct bp_key *key);
extern bool bkeys_pubkey_append(struct bp_keystore *ks, const bu160_t *key_id,
			GString *scriptSig);

#endif /* __LIBCCOIN_KEY_H__ */
