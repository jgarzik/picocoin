// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef LIBCCOIN_BLOOM_H
#define LIBCCOIN_BLOOM_H

#include <stdbool.h>
#include <ccoin/buffer.h>
#include <ccoin/cstr.h>

// 20,000 items with fp rate < 0.1% or 10,000 items and <0.0001%
enum {
	MAX_BLOOM_FILTER_SIZE = 36000, // bytes
	MAX_HASH_FUNCS = 50,
};

struct bloom {
	cstring		*vData;
	unsigned int	nHashFuncs;
};

extern bool bloom_init(struct bloom *bf, unsigned int nElements,double nFPRate);
extern void __bloom_init(struct bloom *bf);
extern void bloom_free(struct bloom *bf);

extern bool deser_bloom(struct bloom *bf, struct const_buffer *buf);
extern void ser_bloom(cstring *s, const struct bloom *bf);

extern void bloom_insert(struct bloom *bf, const void *data, size_t data_len);
extern bool bloom_contains(struct bloom *bf, const void *data, size_t data_len);

extern bool bloom_size_ok(const struct bloom *bf);

#endif /* LIBCCOIN_BLOOM_H */
