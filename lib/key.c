/* Copyright 2012 exMULTI, Inc.
 * Copyright (c) 2009-2012 The Bitcoin developers
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "picocoin-config.h"
#include <ccoin/key.h>

#include <lax_der_privatekey_parsing.c>
#include <lax_der_parsing.c>
#include <openssl/rand.h>
#include <string.h>

static secp256k1_context *s_context = NULL;
secp256k1_context *get_secp256k1_context()
{
	if (!s_context) {
		secp256k1_context *ctx = secp256k1_context_create(
			SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);

		if (!ctx) {
			return NULL;
		}

		uint8_t seed[32];
		if (!RAND_bytes(seed, sizeof(seed)) ||
		    !secp256k1_context_randomize(ctx, seed)) {
			secp256k1_context_destroy(ctx);
			return NULL;
		}

		s_context = ctx;
	}

	return s_context;
}

void bp_key_static_shutdown()
{
	if (s_context) {
		secp256k1_context_destroy(s_context);
		s_context = NULL;
	}
}

bool bp_key_init(struct bp_key *key)
{
	memset(key->secret, 0, sizeof(key->secret));
	return true;
}

void bp_key_free(struct bp_key *key)
{
}

bool bp_key_generate(struct bp_key *key)
{
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	// Keep trying until public key generation passes (random
	// secret is valid).

	do {
		if (!RAND_bytes(key->secret, (int )sizeof(key->secret))) {
			return false;
		}
	} while (!secp256k1_ec_pubkey_create(ctx, &key->pubkey, key->secret));
	return true;
}

bool bp_privkey_set(struct bp_key *key, const void *privkey, size_t pk_len)
{
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	if (ec_privkey_import_der(ctx, key->secret, privkey, pk_len)) {
		if (secp256k1_ec_pubkey_create(ctx, &key->pubkey, key->secret)) {
			return true;
		}
	}
	return false;
}

bool bp_pubkey_set(struct bp_key *key, const void *pubkey, size_t pk_len)
{
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	if (secp256k1_ec_pubkey_parse(ctx, &key->pubkey, pubkey, pk_len)) {
		memset(key->secret, 0, sizeof(key->secret));
		return true;
	}
	return false;
}

bool bp_key_secret_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	if (sizeof(key->secret) == pk_len) {
		memcpy(key->secret, privkey_, sizeof(key->secret));
		if (secp256k1_ec_pubkey_create(ctx, &key->pubkey, key->secret)) {
			return true;
		}
	}
	return false;
}

bool bp_privkey_get(const struct bp_key *key, void **privkey, size_t *pk_len)
{
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	if (secp256k1_ec_seckey_verify(ctx, key->secret)) {
		void *pk = malloc(279);
		if (pk) {
			if (ec_privkey_export_der(ctx, pk, pk_len, key->secret, 1)) {
				*privkey = pk;
				return true;
			}
			free(pk);
		}
	}
	return false;
}

bool bp_pubkey_get(const struct bp_key *key, void **pubkey, size_t *pk_len)
{
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	void *pk = malloc(33);
	if (pk) {
		*pk_len = 33;
		if (secp256k1_ec_pubkey_serialize(ctx, pk, pk_len,
						  &key->pubkey,
						  SECP256K1_EC_COMPRESSED)) {
			*pubkey = pk;
			return true;
		}
		free(pk);
	}
	return false;
}

bool bp_key_secret_get(void *p, size_t len, const struct bp_key *key)
{
	if (!p || sizeof(key->secret) > len) {
		return false;
	}

	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	if (!secp256k1_ec_seckey_verify(ctx, key->secret)) {
		return false;
	}

	memcpy(p, key->secret, sizeof(key->secret));
	return true;
}

bool bp_pubkey_checklowS(const void *sig_, size_t sig_len)
{
    secp256k1_ecdsa_signature sig;

	secp256k1_context *ctx = get_secp256k1_context();
    if (!ctx) {
		return false;
    }

    if (!ecdsa_signature_parse_der_lax(ctx, &sig, sig_, sig_len)) {
		return false;
    }

    return (!secp256k1_ecdsa_signature_normalize(ctx, NULL, &sig));
}

bool bp_sign(const struct bp_key *key, const void *data, size_t data_len,
	     void **sig_out, size_t *sig_len_out)
{
	*sig_out = NULL;
	*sig_len_out = 0;

	secp256k1_ecdsa_signature sig;

	if (32 != data_len) {
		return false;
	}

	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	if (!secp256k1_ec_seckey_verify(ctx, key->secret)) {
		return false;
	}

	if (!secp256k1_ecdsa_sign(ctx, &sig,
				  data,
				  key->secret,
				  secp256k1_nonce_function_rfc6979,
				  NULL)) {
		return false;
	}

	size_t sig_len = 72;
	void *sig_p = malloc(sig_len);
	if (!sig_p)
		return false;

	if (!secp256k1_ecdsa_signature_serialize_der(ctx, sig_p, &sig_len, &sig)) {
		free(sig_p);
		return false;
	}

	*sig_out = sig_p;
	*sig_len_out = sig_len;
	return true;
}

bool bp_verify(const struct bp_key *key, const void *data, size_t data_len,
	       const void *sig_, size_t sig_len)
{
	if (32 != data_len) {
		return false;
	}

	secp256k1_ecdsa_signature sig;
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	if (ecdsa_signature_parse_der_lax(ctx, &sig, sig_, sig_len)) {
		secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);
		return secp256k1_ecdsa_verify(ctx, &sig, data, &key->pubkey);
	}

	return false;
}

bool bp_key_add_secret(struct bp_key *out,
		       const struct bp_key *key,
		       const uint8_t *tweak32)
{
	secp256k1_context *ctx = get_secp256k1_context();
	if (!ctx) {
		return false;
	}

	// If the secret is valid, tweak it and calculate the
	// resulting public key.  Otherwise tweak the public key (and
	// ensure the output private key is invalid).

	if (secp256k1_ec_seckey_verify(ctx, key->secret)) {

		memcpy(out->secret, key->secret, sizeof(key->secret));
		if (secp256k1_ec_privkey_tweak_add(ctx, out->secret, tweak32)) {
			return secp256k1_ec_pubkey_create(
				ctx, &out->pubkey, out->secret);
		}

		return false;
	}

	memset(out->secret, 0, sizeof(out->secret));
	memcpy(&out->pubkey, &key->pubkey, sizeof(secp256k1_pubkey));
	return secp256k1_ec_pubkey_tweak_add(ctx, &out->pubkey, tweak32);
}
