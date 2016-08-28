/* Copyright 2016 BitPay, Inc.
 * Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/hdkeys.h>
#include <ccoin/buffer.h>
#include <ccoin/serialize.h>
#include <ccoin/util.h>

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ripemd.h>

#define MAIN_PUBLIC 0x0488B21E
#define MAIN_PRIVATE 0x0488ADE4
#define TEST_PUBLIC 0x043587CF
#define TEST_PRIVATE 0x04358394

bool hd_extended_key_init(struct hd_extended_key *ek)
{
	if (bp_key_init(&ek->key)) {
		memset(ek->chaincode.data, 0, sizeof(ek->chaincode.data));
		ek->index = 0;
		ek->version = 0;
		memset(ek->parent_fingerprint, 0, 4);
		ek->depth = 0;
		return true;
	}
	return false;
}

void hd_extended_key_free(struct hd_extended_key *ek)
{
	bp_key_free(&ek->key);
}

bool hd_extended_key_deser(struct hd_extended_key *ek, const void *_data,
			   size_t len)
{
	if (78 != len && 82 != len) return false;

	struct const_buffer buf = { _data, len };
	uint32_t version;

	if (!deser_u32(&version, &buf)) return false;
	ek->version = version = be32toh(version);
	if (!deser_bytes(&ek->depth, &buf, 1)) return false;
	if (!deser_bytes(&ek->parent_fingerprint, &buf, 4)) return false;
	if (!deser_u32(&ek->index, &buf)) return false;
	ek->index = be32toh(ek->index);
	if (!deser_bytes(&ek->chaincode.data, &buf, 32)) return false;

	if (MAIN_PUBLIC == version || TEST_PUBLIC == version) {
		if (bp_pubkey_set(&ek->key, buf.p, 33)) {
			return true;
		}
	} else if (MAIN_PRIVATE == version || TEST_PRIVATE == version) {
		uint8_t zero;
		if (deser_bytes(&zero, &buf, 1) && 0 == zero) {
			if (bp_key_secret_set(&ek->key, buf.p, 32)) {
				return true;
			}
		}
	}

	return false;
}

static void hd_extended_key_ser_base(const struct hd_extended_key *ek,
				     cstring *s, uint32_t version)
{
	ser_u32(s, htobe32(version));
	ser_bytes(s, &ek->depth, 1);
	ser_bytes(s, &ek->parent_fingerprint, 4);
	ser_u32(s, htobe32(ek->index));
	ser_bytes(s, &ek->chaincode, 32);
}

bool hd_extended_key_ser_pub(const struct hd_extended_key *ek, cstring *s)
{
	hd_extended_key_ser_base(ek, s, MAIN_PUBLIC);

	void *pub;
	size_t pub_len;
	if (bp_pubkey_get(&ek->key, &pub, &pub_len) && 33 == pub_len) {
		ser_bytes(s, pub, 33);
		free(pub);
		return true;
	}
	return false;
}

bool hd_extended_key_ser_priv(const struct hd_extended_key *ek, cstring *s)
{
	hd_extended_key_ser_base(ek, s, MAIN_PRIVATE);

	const uint8_t zero = 0;
	ser_bytes(s, &zero, 1);
	return bp_key_secret_get(s->str + s->len, 32, &ek->key);
}

bool hd_extended_key_generate_master(struct hd_extended_key *ek,
				     const void *seed, size_t seed_len)
{
	static const uint8_t key[12] = "Bitcoin seed";
	uint8_t I[64];
	HMAC(EVP_sha512(), key, (int)sizeof(key), (const uint8_t *)seed,
	     (uint32_t)seed_len, &I[0], NULL);

	if (bp_key_secret_set(&ek->key, I, 32)) {
		memcpy(ek->chaincode.data, &I[32], 32);
		ek->index = 0;
		ek->version = MAIN_PRIVATE; // get's set public / private during
		memset(ek->parent_fingerprint, 0, 4);
		ek->depth = 0;

		return true;
	}

	return false;
}

bool hd_extended_key_generate_child(const struct hd_extended_key *parent,
				    uint32_t index,
				    struct hd_extended_key *out_child)
{
	bool result = false;
	void *parent_pub = NULL;
	size_t parent_pub_len = 0;

	uint8_t data[33 + sizeof(uint32_t)];
	if (0 != (0x80000000 & index)) {

		if (!bp_key_secret_get(&data[1], 32, &parent->key)) {
			return false;
		}
		data[0] = 0;

		if (!bp_pubkey_get(&parent->key, &parent_pub, &parent_pub_len)) {
			return false;
		}

	} else {

		if (!bp_pubkey_get(&parent->key, &parent_pub, &parent_pub_len)) {
			return false;
		}
		memcpy(&data[0], parent_pub, parent_pub_len);

	}

	if (33 != parent_pub_len) {
		goto free_parent_pub;
	}

	const uint32_t indexBE = htobe32(index);
	memcpy(&data[33], &indexBE, sizeof(uint32_t));

	uint8_t I[64];
	if (NULL == HMAC(EVP_sha512(), parent->chaincode.data,
			 (int)sizeof(parent->chaincode.data), data,
			 (int)sizeof(data), &I[0], NULL)) {
		goto free_parent_pub;
	}

	if (!bp_key_add_secret(&out_child->key, &parent->key, I)) {
		goto free_parent_pub;
	}

	uint8_t md160[RIPEMD160_DIGEST_LENGTH];
	bu_Hash160(md160, parent_pub, parent_pub_len);

	memcpy(out_child->chaincode.data, &I[32], 32);
	out_child->index = index;
	out_child->version = parent->version;
	memcpy(out_child->parent_fingerprint, md160, 4);
	out_child->depth = parent->depth + 1;
	result = true;

free_parent_pub:
	free(parent_pub);

	return result;
}

bool hd_derive(struct hd_extended_key *out_child,
	       const struct hd_extended_key *parent_,
	       const struct hd_path_seg *hdpath,
	       size_t hdpath_len)
{
	struct hd_extended_key parent;
	memcpy(&parent, parent_, sizeof(parent));

	unsigned int i;
	for (i = 0; i < hdpath_len; i++) {
		bool is_last = (i == (hdpath_len - 1));

		uint32_t val = hdpath[i].index;
		if (hdpath[i].hardened)
			val |= 0x80000000;

		struct hd_extended_key tmp;
		struct hd_extended_key *target = &tmp;
		if (is_last)
			target = out_child;

		if (!hd_extended_key_init(&tmp) ||
		    !hd_extended_key_generate_child(&parent, val, target))
			return false;

		if (!is_last)
			memcpy(&parent, &tmp, sizeof(tmp));
	}

	return true;
}

