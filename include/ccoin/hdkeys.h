#ifndef __LIBCCOIN_HDKEYS_H__
#define __LIBCCOIN_HDKEYS_H__
/* Copyright 2016 BitPay, Inc.
 * Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/key.h>

#ifdef __cplusplus
extern "C" {
#endif

struct hd_chaincode {
	uint8_t		data[32];
};

struct hd_extended_key {
	struct bp_key		key;
	struct hd_chaincode	chaincode;
	uint32_t		index;
	uint32_t		version;
	uint8_t			parent_fingerprint[4];
	uint8_t			depth;
};

extern bool hd_extended_key_init(struct hd_extended_key *ek);

extern void hd_extended_key_free(struct hd_extended_key *ek);

extern bool hd_extended_key_deser(struct hd_extended_key *ek, const void *data,
				  size_t len);
extern bool hd_extended_key_ser_pub(const struct hd_extended_key *ek,
				    cstring *s);
extern bool hd_extended_key_ser_priv(const struct hd_extended_key *ek,
				     cstring *s);

extern bool hd_extended_key_generate_master(struct hd_extended_key *ek,
					    const void *seed, size_t seed_len);

extern bool hd_extended_key_generate_child(const struct hd_extended_key *ek,
					   uint32_t index,
					   struct hd_extended_key *out_priv);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_HDKEY_H__ */
