#ifndef __LIBCCOIN_CSTR_H__
#define __LIBCCOIN_CSTR_H__
/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct cstring {
	char	*str;		// string data, incl. NUL
	size_t	len;		// length of string, not including NUL
	size_t	alloc;		// total allocated buffer length
} cstring;

extern cstring *cstr_new(const char *init_str);
extern cstring *cstr_new_sz(size_t sz);
extern cstring *cstr_new_buf(const void *buf, size_t sz);
extern void cstr_free(cstring *s, bool free_buf);

extern bool cstr_equal(const cstring *a, const cstring *b);
extern bool cstr_resize(cstring *s, size_t sz);
extern bool cstr_erase(cstring *s, size_t pos, ssize_t len);

extern bool cstr_append_buf(cstring *s, const void *buf, size_t sz);

static inline bool cstr_append_c(cstring *s, char ch)
{
	return cstr_append_buf(s, &ch, 1);
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_CSTR_H__ */
