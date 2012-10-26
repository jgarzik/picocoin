#ifndef __PICOCOIN_KEY_H__
#define __PICOCOIN_KEY_H__

#include <stdbool.h>
#include <openssl/ec.h>

struct bp_key {
	EC_KEY		*k;
};

extern bool bp_key_init(struct bp_key *key);
extern void bp_key_free(struct bp_key *key);
extern bool bp_key_generate(struct bp_key *key);
extern void bp_privkey_set(struct bp_key *key, void *privkey, size_t pk_len);
extern void bp_pubkey_set(struct bp_key *key, void *pubkey, size_t pk_len);
extern bool bp_privkey_get(struct bp_key *key, void **privkey, size_t *pk_len);
extern bool bp_pubkey_get(struct bp_key *key, void **pubkey, size_t *pk_len);
extern bool bp_sign(struct bp_key *key, const void *data, size_t data_len,
	     void **sig_, size_t *sig_len_);
extern bool bp_verify(struct bp_key *key, const void *data, size_t data_len,
	       const void *sig, size_t sig_len);

#endif /* __PICOCOIN_KEY_H__ */
