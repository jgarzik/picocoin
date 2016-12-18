#ifndef __LIBCCOIN_AES_UTIL_H__
#define __LIBCCOIN_AES_UTIL_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/cstr.h>                 // for cstring

#include <stdbool.h>                    // for bool
#include <stddef.h>                     // for size_t
#include <string.h>                     // for memcpy, memset


#ifdef __cplusplus
extern "C" {
#endif

#define AES256_BLOCK_LENGTH             16
#define AES256_KEY_LENGTH               32

#define MEMSET_BZERO(p,l)     memset((p), 0, (l))
#define MEMCPY_BCOPY(d,s,l)   memcpy((d), (s), (l))

extern cstring *read_aes_file(const char *filename, void *key, size_t key_len,
			      size_t max_file_len);
extern bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_AES_UTIL_H__ */
