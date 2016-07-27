/* Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/util.h>
#include <ccoin/cstr.h>
#include <ccoin/aes_util.h>
#include <ccoin/crypto/aes.h>
#include <ccoin/crypto/sha2.h>

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
static bool ccoin_aes_init(const uint8_t *key_data,
			   int key_data_len,
			   uint8_t *salt_8,
			   uint8_t *iv_32,
			   aes_encrypt_ctx *e_ctx,
			   aes_decrypt_ctx *d_ctx)
{
	int nrounds = 1721;

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to
	 * hash the supplied key material.  nrounds is the number of
	 * times the we hash the material. More rounds are more secure
	 * but slower.
	 */

	/*
	 * hash^nrounds( key_data || salt )
	 *   == hash^(nrounds-1)( hash(key_data || salt) )
	 */

	uint8_t _hash0[64];
	uint8_t _hash1[64];

	{
		SHA512_CTX ctx;
		sha512_Init(&ctx);
		sha512_Update(&ctx, key_data, key_data_len);
		sha512_Update(&ctx, salt_8, 8);
		sha512_Final(_hash0, &ctx);
	}
	--nrounds;

	uint8_t *tmp;
	uint8_t *hash0 = _hash0;
	uint8_t *hash1 = _hash1;
	while (0 < nrounds)
	{
		sha512_Raw(hash0, 64, hash1);
		tmp = hash1;
		hash1 = hash0;
		hash0 = tmp;

		--nrounds;
	}

	/*
	 * hash0 contains the data.  First 32 bytes are key data, the
	 * last are the IV.
	 */

	aes_encrypt_key256(hash0, e_ctx);
	aes_decrypt_key256(hash0, d_ctx);
	memcpy(iv_32, hash0+32, 32);

	return true;
}

static uint8_t *ccoin_aes_encrypt(aes_encrypt_ctx *ctx,
				  uint8_t *iv,
				  const void *_plaintext,
				  const size_t pt_len,
				  size_t *out_len)
{
	const size_t total_blocks = (pt_len / AES_BLOCK_SIZE) + 1;
	const size_t out_size = total_blocks * AES_BLOCK_SIZE;
	const size_t padding = out_size - pt_len;

	const size_t msg_whole_blocks = total_blocks - 1;
	const size_t msg_remainder_offset = msg_whole_blocks * AES_BLOCK_SIZE;
	const size_t msg_remainder_size = pt_len - msg_remainder_offset;

	/* assert(msg_remainder_size == (AES_BLOCK_SIZE - padding)); */

	uint8_t *out = (uint8_t *)malloc(out_size);
	if (msg_whole_blocks)
	{
		aes_cbc_encrypt(_plaintext, out, msg_remainder_offset, iv, ctx);
	}

	uint8_t final_block[AES_BLOCK_SIZE];
	uint8_t *plaintext = (uint8_t *)_plaintext;
	if (msg_remainder_size)
	{
		memcpy(final_block,
		       plaintext + msg_remainder_offset,
		       msg_remainder_size);
	}

	memset(final_block + msg_remainder_size, (uint8_t )padding, padding);

	aes_cbc_encrypt(final_block,
			&out[msg_remainder_offset],
			AES_BLOCK_SIZE,
			iv,
			ctx);

	*out_len = out_size;
	return out;
}

/*
 * Decrypt *len bytes of ciphertext
 */
static uint8_t *ccoin_aes_decrypt(aes_decrypt_ctx *ctx,
				  uint8_t *iv,
				  const uint8_t *ciphertext,
				  size_t ct_len,
				  size_t *out_len)
{
	if (0 != (ct_len % AES_BLOCK_SIZE)) {
		return NULL;
	}

	uint8_t *out_pt = (uint8_t *)malloc(ct_len);
	if (!out_pt) {
		return NULL;
	}

	aes_cbc_decrypt(ciphertext, out_pt, ct_len, iv, ctx);

	const size_t pad_len = out_pt[ct_len-1];
	if (pad_len > ct_len) {
		free(out_pt);
		return NULL;
	}

	*out_len = ct_len - pad_len;
	return out_pt;
}

void *encrypt_aes_buffer(const void *plaintext, size_t pt_len,
			 const void *key, size_t key_len,
			 size_t *ct_len)
{
	aes_encrypt_ctx e_ctx;
	aes_decrypt_ctx d_ctx;
	uint8_t iv[32];
	unsigned int salt[] = { 4185398345U, 2729682459U };
	if (!ccoin_aes_init(key, key_len, (uint8_t *)salt, iv, &e_ctx, &d_ctx))
	{
		return NULL;
	}

	*ct_len = pt_len;
	return ccoin_aes_encrypt(&e_ctx, iv, plaintext, pt_len, ct_len);
}

cstring *decrypt_aes_buffer(const void *ciphertext,
			    size_t ct_len,
			    const void *key,
			    size_t key_len)
{
	aes_encrypt_ctx e_ctx;
	aes_decrypt_ctx d_ctx;
	uint8_t iv[32];
	unsigned int salt[] = { 4185398345U, 2729682459U };
	if (!ccoin_aes_init(key, key_len, (uint8_t *)salt, iv, &e_ctx, &d_ctx))
	{
		return NULL;
	}

	size_t pt_len = ct_len;
	void *plaintext =
		ccoin_aes_decrypt(&d_ctx, iv, ciphertext, ct_len, &pt_len);
	if (!plaintext)
	{
		return NULL;
	}

	cstring *ret = cstr_new_buf(plaintext, pt_len);
	free(plaintext);

	return ret;
}
