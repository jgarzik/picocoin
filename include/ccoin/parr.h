#ifndef __LIBCCOIN_PARR_H__
#define __LIBCCOIN_PARR_H__
/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdlib.h>
#include <stdbool.h>

typedef struct parr {
	void		**data;		// array of pointers
	size_t		len;		// array element count
	size_t		alloc;		// allocated array elements

	void		(*elem_free_f)(void *);
} parr;

extern parr *parr_new(size_t res, void (*free_f)(void *));
extern void parr_free(parr *pa, bool free_array);

extern bool parr_add(parr *pa, void *data);
extern bool parr_remove(parr *pa, void *data);
extern void parr_remove_idx(parr *pa, size_t idx);
extern bool parr_resize(parr *pa, size_t newsz);

extern ssize_t parr_find(parr *pa, void *data);

static inline void *parr_idx(parr *pa, size_t idx)
{
	if (idx >= pa->len)
		return NULL;
	return pa->data[idx];
}

#endif /* __LIBCCOIN_PARR_H__ */
