/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright (c) 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/endian.h>
#include <ccoin/crypto/sha1.h>

#include <string.h>

static inline uint32_t ReadBE32(const unsigned char* ptr)
{
    return be32toh(*((uint32_t*)ptr));
}

static inline void WriteBE32(unsigned char* ptr, uint32_t x)
{
    *((uint32_t*)ptr) = htobe32(x);
}

static inline void WriteBE64(unsigned char* ptr, uint64_t x)
{
    *((uint64_t*)ptr) = htobe64(x);
}

/** One round of SHA-1. */
static inline void Round(uint32_t a, uint32_t *b, uint32_t c, uint32_t d,
                         uint32_t *e, uint32_t f, uint32_t k, uint32_t w)
{
    *e += ((a << 5) | (a >> 27)) + f + k + w;
    *b = (*b << 30) | (*b >> 2);
}

static inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d) { return d ^ (b & (c ^ d)); }
static inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d) { return b ^ c ^ d; }
static inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d) { return (b & c) | (d & (b | c)); }

static inline uint32_t left(uint32_t x) { return (x << 1) | (x >> 31); }

/** Initialize SHA-1 state. */
static inline void Initialize(uint32_t* s)
{
    s[0] = 0x67452301ul;
    s[1] = 0xEFCDAB89ul;
    s[2] = 0x98BADCFEul;
    s[3] = 0x10325476ul;
    s[4] = 0xC3D2E1F0ul;
}

static const uint32_t k1 = 0x5A827999ul;
static const uint32_t k2 = 0x6ED9EBA1ul;
static const uint32_t k3 = 0x8F1BBCDCul;
static const uint32_t k4 = 0xCA62C1D6ul;

/** Perform a SHA-1 transformation, processing a 64-byte chunk. */
static void Transform(uint32_t* s, const unsigned char* chunk)
{
    uint32_t a = s[0], b = s[1], c = s[2], d = s[3], e = s[4];
    uint32_t w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15;

    Round(a, &b, c, d, &e, f1(b, c, d), k1, w0 = ReadBE32(chunk + 0));
    Round(e, &a, b, c, &d, f1(a, b, c), k1, w1 = ReadBE32(chunk + 4));
    Round(d, &e, a, b, &c, f1(e, a, b), k1, w2 = ReadBE32(chunk + 8));
    Round(c, &d, e, a, &b, f1(d, e, a), k1, w3 = ReadBE32(chunk + 12));
    Round(b, &c, d, e, &a, f1(c, d, e), k1, w4 = ReadBE32(chunk + 16));
    Round(a, &b, c, d, &e, f1(b, c, d), k1, w5 = ReadBE32(chunk + 20));
    Round(e, &a, b, c, &d, f1(a, b, c), k1, w6 = ReadBE32(chunk + 24));
    Round(d, &e, a, b, &c, f1(e, a, b), k1, w7 = ReadBE32(chunk + 28));
    Round(c, &d, e, a, &b, f1(d, e, a), k1, w8 = ReadBE32(chunk + 32));
    Round(b, &c, d, e, &a, f1(c, d, e), k1, w9 = ReadBE32(chunk + 36));
    Round(a, &b, c, d, &e, f1(b, c, d), k1, w10 = ReadBE32(chunk + 40));
    Round(e, &a, b, c, &d, f1(a, b, c), k1, w11 = ReadBE32(chunk + 44));
    Round(d, &e, a, b, &c, f1(e, a, b), k1, w12 = ReadBE32(chunk + 48));
    Round(c, &d, e, a, &b, f1(d, e, a), k1, w13 = ReadBE32(chunk + 52));
    Round(b, &c, d, e, &a, f1(c, d, e), k1, w14 = ReadBE32(chunk + 56));
    Round(a, &b, c, d, &e, f1(b, c, d), k1, w15 = ReadBE32(chunk + 60));

    Round(e, &a, b, c, &d, f1(a, b, c), k1, w0 = left(w0 ^ w13 ^ w8 ^ w2));
    Round(d, &e, a, b, &c, f1(e, a, b), k1, w1 = left(w1 ^ w14 ^ w9 ^ w3));
    Round(c, &d, e, a, &b, f1(d, e, a), k1, w2 = left(w2 ^ w15 ^ w10 ^ w4));
    Round(b, &c, d, e, &a, f1(c, d, e), k1, w3 = left(w3 ^ w0 ^ w11 ^ w5));
    Round(a, &b, c, d, &e, f2(b, c, d), k2, w4 = left(w4 ^ w1 ^ w12 ^ w6));
    Round(e, &a, b, c, &d, f2(a, b, c), k2, w5 = left(w5 ^ w2 ^ w13 ^ w7));
    Round(d, &e, a, b, &c, f2(e, a, b), k2, w6 = left(w6 ^ w3 ^ w14 ^ w8));
    Round(c, &d, e, a, &b, f2(d, e, a), k2, w7 = left(w7 ^ w4 ^ w15 ^ w9));
    Round(b, &c, d, e, &a, f2(c, d, e), k2, w8 = left(w8 ^ w5 ^ w0 ^ w10));
    Round(a, &b, c, d, &e, f2(b, c, d), k2, w9 = left(w9 ^ w6 ^ w1 ^ w11));
    Round(e, &a, b, c, &d, f2(a, b, c), k2, w10 = left(w10 ^ w7 ^ w2 ^ w12));
    Round(d, &e, a, b, &c, f2(e, a, b), k2, w11 = left(w11 ^ w8 ^ w3 ^ w13));
    Round(c, &d, e, a, &b, f2(d, e, a), k2, w12 = left(w12 ^ w9 ^ w4 ^ w14));
    Round(b, &c, d, e, &a, f2(c, d, e), k2, w13 = left(w13 ^ w10 ^ w5 ^ w15));
    Round(a, &b, c, d, &e, f2(b, c, d), k2, w14 = left(w14 ^ w11 ^ w6 ^ w0));
    Round(e, &a, b, c, &d, f2(a, b, c), k2, w15 = left(w15 ^ w12 ^ w7 ^ w1));

    Round(d, &e, a, b, &c, f2(e, a, b), k2, w0 = left(w0 ^ w13 ^ w8 ^ w2));
    Round(c, &d, e, a, &b, f2(d, e, a), k2, w1 = left(w1 ^ w14 ^ w9 ^ w3));
    Round(b, &c, d, e, &a, f2(c, d, e), k2, w2 = left(w2 ^ w15 ^ w10 ^ w4));
    Round(a, &b, c, d, &e, f2(b, c, d), k2, w3 = left(w3 ^ w0 ^ w11 ^ w5));
    Round(e, &a, b, c, &d, f2(a, b, c), k2, w4 = left(w4 ^ w1 ^ w12 ^ w6));
    Round(d, &e, a, b, &c, f2(e, a, b), k2, w5 = left(w5 ^ w2 ^ w13 ^ w7));
    Round(c, &d, e, a, &b, f2(d, e, a), k2, w6 = left(w6 ^ w3 ^ w14 ^ w8));
    Round(b, &c, d, e, &a, f2(c, d, e), k2, w7 = left(w7 ^ w4 ^ w15 ^ w9));
    Round(a, &b, c, d, &e, f3(b, c, d), k3, w8 = left(w8 ^ w5 ^ w0 ^ w10));
    Round(e, &a, b, c, &d, f3(a, b, c), k3, w9 = left(w9 ^ w6 ^ w1 ^ w11));
    Round(d, &e, a, b, &c, f3(e, a, b), k3, w10 = left(w10 ^ w7 ^ w2 ^ w12));
    Round(c, &d, e, a, &b, f3(d, e, a), k3, w11 = left(w11 ^ w8 ^ w3 ^ w13));
    Round(b, &c, d, e, &a, f3(c, d, e), k3, w12 = left(w12 ^ w9 ^ w4 ^ w14));
    Round(a, &b, c, d, &e, f3(b, c, d), k3, w13 = left(w13 ^ w10 ^ w5 ^ w15));
    Round(e, &a, b, c, &d, f3(a, b, c), k3, w14 = left(w14 ^ w11 ^ w6 ^ w0));
    Round(d, &e, a, b, &c, f3(e, a, b), k3, w15 = left(w15 ^ w12 ^ w7 ^ w1));

    Round(c, &d, e, a, &b, f3(d, e, a), k3, w0 = left(w0 ^ w13 ^ w8 ^ w2));
    Round(b, &c, d, e, &a, f3(c, d, e), k3, w1 = left(w1 ^ w14 ^ w9 ^ w3));
    Round(a, &b, c, d, &e, f3(b, c, d), k3, w2 = left(w2 ^ w15 ^ w10 ^ w4));
    Round(e, &a, b, c, &d, f3(a, b, c), k3, w3 = left(w3 ^ w0 ^ w11 ^ w5));
    Round(d, &e, a, b, &c, f3(e, a, b), k3, w4 = left(w4 ^ w1 ^ w12 ^ w6));
    Round(c, &d, e, a, &b, f3(d, e, a), k3, w5 = left(w5 ^ w2 ^ w13 ^ w7));
    Round(b, &c, d, e, &a, f3(c, d, e), k3, w6 = left(w6 ^ w3 ^ w14 ^ w8));
    Round(a, &b, c, d, &e, f3(b, c, d), k3, w7 = left(w7 ^ w4 ^ w15 ^ w9));
    Round(e, &a, b, c, &d, f3(a, b, c), k3, w8 = left(w8 ^ w5 ^ w0 ^ w10));
    Round(d, &e, a, b, &c, f3(e, a, b), k3, w9 = left(w9 ^ w6 ^ w1 ^ w11));
    Round(c, &d, e, a, &b, f3(d, e, a), k3, w10 = left(w10 ^ w7 ^ w2 ^ w12));
    Round(b, &c, d, e, &a, f3(c, d, e), k3, w11 = left(w11 ^ w8 ^ w3 ^ w13));
    Round(a, &b, c, d, &e, f2(b, c, d), k4, w12 = left(w12 ^ w9 ^ w4 ^ w14));
    Round(e, &a, b, c, &d, f2(a, b, c), k4, w13 = left(w13 ^ w10 ^ w5 ^ w15));
    Round(d, &e, a, b, &c, f2(e, a, b), k4, w14 = left(w14 ^ w11 ^ w6 ^ w0));
    Round(c, &d, e, a, &b, f2(d, e, a), k4, w15 = left(w15 ^ w12 ^ w7 ^ w1));

    Round(b, &c, d, e, &a, f2(c, d, e), k4, w0 = left(w0 ^ w13 ^ w8 ^ w2));
    Round(a, &b, c, d, &e, f2(b, c, d), k4, w1 = left(w1 ^ w14 ^ w9 ^ w3));
    Round(e, &a, b, c, &d, f2(a, b, c), k4, w2 = left(w2 ^ w15 ^ w10 ^ w4));
    Round(d, &e, a, b, &c, f2(e, a, b), k4, w3 = left(w3 ^ w0 ^ w11 ^ w5));
    Round(c, &d, e, a, &b, f2(d, e, a), k4, w4 = left(w4 ^ w1 ^ w12 ^ w6));
    Round(b, &c, d, e, &a, f2(c, d, e), k4, w5 = left(w5 ^ w2 ^ w13 ^ w7));
    Round(a, &b, c, d, &e, f2(b, c, d), k4, w6 = left(w6 ^ w3 ^ w14 ^ w8));
    Round(e, &a, b, c, &d, f2(a, b, c), k4, w7 = left(w7 ^ w4 ^ w15 ^ w9));
    Round(d, &e, a, b, &c, f2(e, a, b), k4, w8 = left(w8 ^ w5 ^ w0 ^ w10));
    Round(c, &d, e, a, &b, f2(d, e, a), k4, w9 = left(w9 ^ w6 ^ w1 ^ w11));
    Round(b, &c, d, e, &a, f2(c, d, e), k4, w10 = left(w10 ^ w7 ^ w2 ^ w12));
    Round(a, &b, c, d, &e, f2(b, c, d), k4, w11 = left(w11 ^ w8 ^ w3 ^ w13));
    Round(e, &a, b, c, &d, f2(a, b, c), k4, w12 = left(w12 ^ w9 ^ w4 ^ w14));
    Round(d, &e, a, b, &c, f2(e, a, b), k4, left(w13 ^ w10 ^ w5 ^ w15));
    Round(c, &d, e, a, &b, f2(d, e, a), k4, left(w14 ^ w11 ^ w6 ^ w0));
    Round(b, &c, d, e, &a, f2(c, d, e), k4, left(w15 ^ w12 ^ w7 ^ w1));

    s[0] += a;
    s[1] += b;
    s[2] += c;
    s[3] += d;
    s[4] += e;
}

////// SHA1

void sha1_Init(SHA1_CTX *ctx)
{
    ctx->bytes = 0;
    Initialize(ctx->s);
}

void sha1_Update(SHA1_CTX *ctx, const unsigned char* data, size_t len)
{
    const unsigned char* end = data + len;
    size_t bufsize = ctx->bytes % 64;
    if (bufsize && bufsize + len >= 64) {
        // Fill the buffer, and process it.
        memcpy(ctx->buf + bufsize, data, 64 - bufsize);
        ctx->bytes += 64 - bufsize;
        data += 64 - bufsize;
        Transform(ctx->s, ctx->buf);
        bufsize = 0;
    }
    while (end >= data + 64) {
        // Process full chunks directly from the source.
        Transform(ctx->s, data);
        ctx->bytes += 64;
        data += 64;
    }
    if (end > data) {
        // Fill the buffer with what remains.
        memcpy(ctx->buf + bufsize, data, end - data);
        ctx->bytes += end - data;
    }
}

void sha1_Final(unsigned char hash[SHA1_DIGEST_LENGTH], SHA1_CTX *ctx)
{
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    WriteBE64(sizedesc, ctx->bytes << 3);
    sha1_Update(ctx, pad, 1 + ((119 - (ctx->bytes % 64)) % 64));
    sha1_Update(ctx, sizedesc, 8);
    WriteBE32(hash, ctx->s[0]);
    WriteBE32(hash + 4, ctx->s[1]);
    WriteBE32(hash + 8, ctx->s[2]);
    WriteBE32(hash + 12, ctx->s[3]);
    WriteBE32(hash + 16, ctx->s[4]);
}

void sha1_Raw(const uint8_t *data, size_t len, uint8_t digest[SHA1_DIGEST_LENGTH])
{
    SHA1_CTX ctx;
    sha1_Init(&ctx);
    sha1_Update(&ctx, data, len);
    sha1_Final(digest, &ctx);
}
