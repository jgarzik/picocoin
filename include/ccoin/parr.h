#ifndef __LIBCCOIN_PARR_H__
#define __LIBCCOIN_PARR_H__
/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdlib.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

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
extern void parr_remove_range(parr *pa, size_t idx, size_t len);
extern bool parr_resize(parr *pa, size_t newsz);

extern ssize_t parr_find(parr *pa, void *data);

#define parr_idx(pa, idx) ((pa)->data[(idx)])

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_PARR_H__ */
