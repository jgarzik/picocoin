/* Copyright 2012 exMULTI, Inc.
 * Copyright (c) 2009-2012 The Bitcoin developers
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/ripemd.h>
#include <openssl/err.h>
#include <ccoin/key.h>

typedef struct {
        int     field_type,     /* either NID_X9_62_prime_field or
                                 * NID_X9_62_characteristic_two_field */
                seed_len,
                param_len;
        unsigned int cofactor;  /* promoted to BN_ULONG */
} EC_CURVE_DATA;

static const struct { EC_CURVE_DATA h; unsigned char data[0+32*6]; }
        _EC_SECG_PRIME_256K1 = {
                { NID_X9_62_prime_field,0,32,1 },
                {                                                       /* no seed */
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,      /* p */
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,
                        0xFC,0x2F,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      /* a */
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,      /* b */
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x07,
                        0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,      /* x */
                        0x62,0x95,0xCE,0x87,0x0B,0x07,0x02,0x9B,0xFC,0xDB,
                        0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,
                        0x17,0x98,
                        0x48,0x3a,0xda,0x77,0x26,0xa3,0xc4,0x65,0x5d,0xa4,      /* y */
                        0xfb,0xfc,0x0e,0x11,0x08,0xa8,0xfd,0x17,0xb4,0x48,
                        0xa6,0x85,0x54,0x19,0x9c,0x47,0xd0,0x8f,0xfb,0x10,
                        0xd4,0xb8,
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,      /* order */
                        0xFF,0xFF,0xFF,0xFF,0xFF,0xFE,0xBA,0xAE,0xDC,0xE6,
                        0xAF,0x48,0xA0,0x3B,0xBF,0xD2,0x5E,0x8C,0xD0,0x36,
                        0x41,0x41 }
        };

static EC_GROUP *ec_group_new_from_data(const EC_CURVE_DATA *data)
{
        EC_GROUP *group=NULL;
        EC_POINT *P=NULL;
        BN_CTX   *ctx=NULL;
        BIGNUM   *p=NULL, *a=NULL, *b=NULL, *x=NULL, *y=NULL, *order=NULL;
        int      ok=0;
        int      seed_len,param_len;
        const unsigned char *params;

        if ((ctx = BN_CTX_new()) == NULL)
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_MALLOC_FAILURE);
                        goto err;
                }

        seed_len  = data->seed_len;
        param_len = data->param_len;
        params    = (const unsigned char *)(data+1);    /* skip header */
        params   += seed_len;                           /* skip seed   */

        if (!(p = BN_bin2bn(params+0*param_len, param_len, NULL))
            || !(a = BN_bin2bn(params+1*param_len, param_len, NULL))
            || !(b = BN_bin2bn(params+2*param_len, param_len, NULL)))
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
                        goto err;
                }

        if ((group = EC_GROUP_new_curve_GFp(p, a, b, ctx)) == NULL)
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
                        goto err;
                }

        if ((P = EC_POINT_new(group)) == NULL)
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
                        goto err;
                }

        if (!(x = BN_bin2bn(params+3*param_len, param_len, NULL))
            || !(y = BN_bin2bn(params+4*param_len, param_len, NULL)))
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
                        goto err;
                }
        if (!EC_POINT_set_affine_coordinates_GFp(group, P, x, y, ctx))
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
                        goto err;
                }
        if (!(order = BN_bin2bn(params+5*param_len, param_len, NULL))
            || !BN_set_word(x, (BN_ULONG)data->cofactor))
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_BN_LIB);
                        goto err;
                }
        if (!EC_GROUP_set_generator(group, P, order, x))
                {
                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
                        goto err;
                }
        if (seed_len)
                {
                        if (!EC_GROUP_set_seed(group, params-seed_len, seed_len))
                                {
                                        ECerr(EC_F_EC_GROUP_NEW_FROM_DATA, ERR_R_EC_LIB);
                                        goto err;
                                }
                }
        ok=1;
 err:
        if (!ok)
                {
                        EC_GROUP_free(group);
                        group = NULL;
                }
        if (P)
                EC_POINT_free(P);
        if (ctx)
                BN_CTX_free(ctx);
        if (p)
                BN_free(p);
        if (a)
                BN_free(a);
        if (b)
                BN_free(b);
        if (order)
                BN_free(order);
        if (x)
                BN_free(x);
        if (y)
                BN_free(y);
        return group;
}


EC_KEY *EC_KEY_new_by_curve_name_NID_secp256k1(void)
{
        static EC_GROUP *group = NULL;
        EC_KEY *ret = NULL;

        if (group == NULL) {
                group = EC_GROUP_new_by_curve_name(NID_secp256k1);
                if (group == NULL)
                        group = ec_group_new_from_data(&_EC_SECG_PRIME_256K1.h);
                if (group == NULL)
                        return NULL;
        }

        ret = EC_KEY_new();
        if (ret == NULL)
                return NULL;

        EC_KEY_set_group(ret, group);

        return ret;
}


/* Generate a private key from just the secret parameter */
static int EC_KEY_regenerate_key(EC_KEY *eckey, BIGNUM *priv_key)
{
	int ok = 0;
	BN_CTX *ctx = NULL;
	EC_POINT *pub_key = NULL;

	if (!eckey) return 0;

	const EC_GROUP *group = EC_KEY_get0_group(eckey);

	if ((ctx = BN_CTX_new()) == NULL)
		goto err;

	pub_key = EC_POINT_new(group);

	if (pub_key == NULL)
		goto err;

	if (!EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, ctx))
		goto err;

	EC_KEY_set_private_key(eckey,priv_key);
	EC_KEY_set_public_key(eckey,pub_key);

	ok = 1;

err:

	if (pub_key)
		EC_POINT_free(pub_key);
	if (ctx != NULL)
		BN_CTX_free(ctx);

	return(ok);
}

bool bp_key_init(struct bp_key *key)
{
	memset(key, 0, sizeof(*key));

	key->k = EC_KEY_new_by_curve_name_NID_secp256k1();
	if (!key->k)
		return false;

	return true;
}

void bp_key_free(struct bp_key *key)
{
	if (key->k) {
		EC_KEY_free(key->k);
		key->k = NULL;
	}
}

bool bp_key_generate(struct bp_key *key)
{
	if (!key->k)
		return false;

	if (!EC_KEY_generate_key(key->k))
		return false;
	if (!EC_KEY_check_key(key->k))
		return false;

	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);

	return true;
}

bool bp_privkey_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	const unsigned char *privkey = privkey_;
	if (!d2i_ECPrivateKey(&key->k, &privkey, pk_len))
		return false;
	if (!EC_KEY_check_key(key->k))
		return false;

	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);

	return true;
}

bool bp_pubkey_set(struct bp_key *key, const void *pubkey_, size_t pk_len)
{
	const unsigned char *pubkey = pubkey_;
	if (!o2i_ECPublicKey(&key->k, &pubkey, pk_len))
		return false;
	if (pk_len == 33)
		EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);
	return true;
}

bool bp_key_secret_set(struct bp_key *key, const void *privkey_, size_t pk_len)
{
	bp_key_free(key);

	if (!privkey_ || pk_len != 32)
		return false;

	const unsigned char *privkey = privkey_;
	BIGNUM *bn = BN_bin2bn(privkey, 32, BN_new());
	if (!bn)
		return false;

	key->k = EC_KEY_new_by_curve_name_NID_secp256k1();
	if (!key->k)
		goto err_out;

	if (!EC_KEY_regenerate_key(key->k, bn))
		goto err_out;
	if (!EC_KEY_check_key(key->k))
		return false;

	EC_KEY_set_conv_form(key->k, POINT_CONVERSION_COMPRESSED);

	BN_clear_free(bn);
	return true;

err_out:
	bp_key_free(key);
	BN_clear_free(bn);
	return false;
}

bool bp_privkey_get(const struct bp_key *key, void **privkey, size_t *pk_len)
{
	if (!EC_KEY_check_key(key->k))
		return false;

	size_t sz = i2d_ECPrivateKey(key->k, 0);
	unsigned char *orig_mem, *mem = malloc(sz);
	orig_mem = mem;
	i2d_ECPrivateKey(key->k, &mem);

	*privkey = orig_mem;
	*pk_len = sz;

	return true;
}

bool bp_pubkey_get(const struct bp_key *key, void **pubkey, size_t *pk_len)
{
	if (!EC_KEY_check_key(key->k))
		return false;

	size_t sz = i2o_ECPublicKey(key->k, 0);
	unsigned char *orig_mem, *mem = malloc(sz);
	orig_mem = mem;
	i2o_ECPublicKey(key->k, &mem);

	*pubkey = orig_mem;
	*pk_len = sz;

	return true;
}

bool bp_key_secret_get(void *p, size_t len, const struct bp_key *key)
{
	if (!p || len < 32 || !key)
		return false;

	/* zero buffer */
	memset(p, 0, len);

	/* get bignum secret */
	const BIGNUM *bn = EC_KEY_get0_private_key(key->k);
	if (!bn)
		return false;
	int nBytes = BN_num_bytes(bn);

	/* store secret at end of buffer */
	int n = BN_bn2bin(bn, p + (len - nBytes));
	if (n != nBytes)
		return false;

	return true;
}

bool bp_sign(const struct bp_key *key, const void *data, size_t data_len,
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

bool bp_verify(const struct bp_key *key, const void *data, size_t data_len,
	       const void *sig_, size_t sig_len)
{
	const unsigned char *sig = sig_;
	ECDSA_SIG *esig;
	bool b = false;

	esig = ECDSA_SIG_new();
	if (!esig)
		goto out;

	if (!d2i_ECDSA_SIG(&esig, &sig, sig_len))
		goto out_free;

	b = ECDSA_do_verify(data, data_len, esig, key->k) == 1;

out_free:
	ECDSA_SIG_free(esig);
out:
	return b;
}

