#ifndef __LIBCCOIN_HEXCODE_H__
#define __LIBCCOIN_HEXCODE_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <ccoin/cstr.h>

#ifdef __cplusplus
extern "C" {
#endif

extern bool decode_hex(void *p, size_t max_len, const char *hexstr, size_t *out_len_);
extern void encode_hex(char *hexstr, const void *p_, size_t len);
extern cstring *hex2str(const char *hexstr);
extern bool is_hexstr(const char *hexstr, bool require_prefix);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_HEXCODE_H__ */
