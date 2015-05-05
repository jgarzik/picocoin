// Copyright (c) 2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include <math.h>
#include <stdlib.h>

#include <string.h>
#include <ccoin/buffer.h>
#include <ccoin/bloom.h>
#include <ccoin/serialize.h>
#include <ccoin/cstr.h>
#include <ccoin/util.h>

#define LN2SQUARED 0.4804530139182014246671025263266649717305529515945455L
#define LN2 0.6931471805599453094172321214581765680755001343602552L

static const unsigned char bit_mask[8] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80};

static inline uint32_t ROTL32 ( uint32_t x, int8_t r )
{
  return (x << r) | (x >> (32 - r));
}

static unsigned int bloom_hash(struct bloom *bf, unsigned int nHashNum,
				   struct const_buffer *vDataToHash_)
{
	// The following is MurmurHash3 (x86_32), see http://code.google.com/p/smhasher/source/browse/trunk/MurmurHash3.cpp
	uint32_t h1 = nHashNum * (0xffffffffU / (bf->nHashFuncs-1));
	const uint32_t c1 = 0xcc9e2d51;
	const uint32_t c2 = 0x1b873593;
	const unsigned char *vDataToHash = vDataToHash_->p;

	const int nblocks = vDataToHash_->len / 4;

	//----------
	// body
	const uint32_t * blocks = (const uint32_t *)(&vDataToHash[0] + nblocks*4);

	int i;
	for(i = -nblocks; i; i++)
	{
		uint32_t k1 = blocks[i];

		k1 *= c1;
		k1 = ROTL32(k1,15);
		k1 *= c2;

		h1 ^= k1;
		h1 = ROTL32(h1,13);
		h1 = h1*5+0xe6546b64;
	}

	//----------
	// tail
	const uint8_t * tail = (const uint8_t*)(&vDataToHash[0] + nblocks*4);

	uint32_t k1 = 0;

	switch(vDataToHash_->len & 3)
	{
	case 3: k1 ^= tail[2] << 16;
	case 2: k1 ^= tail[1] << 8;
	case 1: k1 ^= tail[0];
			k1 *= c1; k1 = ROTL32(k1,15); k1 *= c2; h1 ^= k1;
	};

	//----------
	// finalization
	h1 ^= vDataToHash_->len;
	h1 ^= h1 >> 16;
	h1 *= 0x85ebca6b;
	h1 ^= h1 >> 13;
	h1 *= 0xc2b2ae35;
	h1 ^= h1 >> 16;

	return h1 % (bf->vData->len * 8);
}

static void string_resize(cstring *s, unsigned int new_index)
{
	unsigned int new_size = new_index + 1;
	unsigned int cur_size = s->len;
	if (cur_size >= new_size)
		return;

	cstr_resize(s, new_size);

	unsigned int pad = new_size - cur_size;
	memset(s->str + cur_size, 0, pad);
}

void bloom_insert(struct bloom *bf, const void *data, size_t data_len)
{
	struct const_buffer vKey = { data, data_len };
	unsigned int i;
	for (i = 0; i < bf->nHashFuncs; i++)
	{
		unsigned int nIndex = bloom_hash(bf, i, &vKey);
		string_resize(bf->vData, nIndex >> 3);
		bf->vData->str[nIndex >> 3] |= bit_mask[7 & nIndex];
	}
}

bool bloom_contains(struct bloom *bf, const void *data, size_t data_len)
{
	struct const_buffer vKey = { data, data_len };
	unsigned int i;
	for (i = 0; i < bf->nHashFuncs; i++)
	{
		unsigned int nIndex = bloom_hash(bf, i, &vKey);
		string_resize(bf->vData, nIndex >> 3);
		if (!(bf->vData->str[nIndex >> 3] & bit_mask[7 & nIndex]))
			return false;
	}
	return true;
}

bool bloom_size_ok(const struct bloom *bf)
{
	return bf->vData->len <= MAX_BLOOM_FILTER_SIZE &&
	       bf->nHashFuncs <= MAX_HASH_FUNCS;
}

bool deser_bloom(struct bloom *bf, struct const_buffer *buf)
{
	if (!deser_varstr(&bf->vData, buf)) return false;
	if (!deser_u32(&bf->nHashFuncs, buf)) return false;
	return true;
}

void ser_bloom(cstring *s, const struct bloom *bf)
{
	ser_varstr(s, bf->vData);
	ser_u32(s, bf->nHashFuncs);
}

bool bloom_init(struct bloom *bf, unsigned int nElements, double nFPRate)
{
	memset(bf, 0, sizeof(*bf));

	unsigned int filter_size =
	MIN((unsigned int)(-1 / LN2SQUARED * nElements * log(nFPRate)), MAX_BLOOM_FILTER_SIZE * 8) / 8;

	bf->vData = cstr_new_sz(filter_size);
	string_resize(bf->vData, filter_size - 1);

	bf->nHashFuncs =
	MIN((unsigned int)(bf->vData->len * 8 / nElements * LN2), MAX_HASH_FUNCS);

	return true;
}

void __bloom_init(struct bloom *bf)
{
	memset(bf, 0, sizeof(*bf));
}

void bloom_free(struct bloom *bf)
{
	if (bf->vData) {
		cstr_free(bf->vData, true);
		bf->vData = NULL;
	}
}

