#ifndef __LIBCCOIN_SHA1_H__
#define __LIBCCOIN_SHA1_H__
/* Copyright (c) 2014 The Bitcoin Core developers
 * Copyright (c) 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHA1_DIGEST_LENGTH		20

typedef struct _SHA1_CTX {
    uint32_t   s[5];
    uint8_t    buf[64];
    uint64_t   bytes;
} SHA1_CTX;

void sha1_Init(SHA1_CTX *);
void sha1_Update(SHA1_CTX *, const uint8_t* data, size_t len);
void sha1_Final(uint8_t[SHA1_DIGEST_LENGTH], SHA1_CTX *);
void sha1_Raw(const uint8_t *, size_t, uint8_t[SHA1_DIGEST_LENGTH]);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_SHA1_H__ */
