#ifndef __LIBCCOIN_BUFFER_H__
#define __LIBCCOIN_BUFFER_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct buffer {
	void		*p;
	size_t		len;
};

struct const_buffer {
	const void	*p;
	size_t		len;
};

extern unsigned long buffer_hash(const void *key_);
extern bool buffer_equal(const void *a, const void *b);
extern void buffer_free(void *struct_buffer);
extern struct buffer *buffer_copy(const void *data, size_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_BUFFER_H__ */
