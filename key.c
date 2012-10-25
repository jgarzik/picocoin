
#include "picocoin-config.h"

#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include "key.h"

void bp_key_init(struct bp_key *key)
{
	memset(key, 0, sizeof(*key));

	key->k = EC_KEY_new_by_curve_name(NID_secp256k1);
}

void bp_key_free(struct bp_key *key)
{
	EC_KEY_free(key->k);
	key->k = NULL;
}

void bp_privkey_set(struct bp_key *key, void *privkey, size_t pk_len)
{
	d2i_ECPrivateKey(&key->k, privkey, pk_len);
}

void bp_pubkey_set(struct bp_key *key, void *pubkey, size_t pk_len)
{
	o2i_ECPublicKey(&key->k, pubkey, pk_len);
}

void bp_privkey_get(struct bp_key *key, void **privkey, size_t *pk_len)
{
	size_t sz = i2d_ECPrivateKey(key->k, 0);
	void *mem = malloc(sz);
	i2d_ECPrivateKey(key->k, mem);

	*privkey = mem;
	*pk_len = sz;
}

void bp_pubkey_get(struct bp_key *key, void **pubkey, size_t *pk_len)
{
	size_t sz = i2o_ECPublicKey(key->k, 0);
	void *mem = malloc(sz);
	i2o_ECPublicKey(key->k, mem);

	*pubkey = mem;
	*pk_len = sz;
}

bool bp_sign(struct bp_key *key, const void *data, size_t data_len,
	     void **sig_, size_t *sig_len_)
{
	size_t sig_sz = ECDSA_size(key->k);
	void *sig = calloc(1, sig_sz);
	unsigned int sig_sz_out = sig_sz;

	int src = ECDSA_sign(0, data, data_len, sig, &sig_sz_out, key->k);
	if (src != 1) {
		free(sig);
		return false;
	}

	*sig_ = sig;
	*sig_len_ = sig_sz_out;

	return true;
}

bool bp_verify(struct bp_key *key, const void *data, size_t data_len,
	       const void *sig, size_t sig_len)
{
	return ECDSA_verify(0, data, data_len, sig, sig_len, key->k);
}

