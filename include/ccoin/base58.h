#ifndef __LIBCCOIN_BASE58_H__
#define __LIBCCOIN_BASE58_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <ccoin/cstr.h>

#ifdef __cplusplus
extern "C" {
#endif

extern cstring *base58_encode(const void *data_, size_t data_len);
extern cstring *base58_encode_check(unsigned char addrtype, bool have_addrtype,
			     const void *data, size_t data_len);

extern cstring *base58_decode(const char *s_in);
extern cstring *base58_decode_check(unsigned char *addrtype, const char *s_in);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_BASE58_H__ */
