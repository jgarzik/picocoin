#ifndef __LIBCCOIN_CLIST_H__
#define __LIBCCOIN_CLIST_H__
/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct clist {
	void		*data;

	struct clist	*prev;
	struct clist	*next;
} clist;

extern void clist_free_ext(clist *l, void (*free_f)(void *));

static inline void clist_free(clist *l)
{
	clist_free_ext(l, NULL);
}

extern size_t clist_length(clist *l);
extern clist *clist_last(clist *l);
extern clist *clist_append(clist *l, void *buf);
extern clist *clist_prepend(clist *l, void *buf);
extern clist *clist_delete(clist *l, clist *link);
extern clist *clist_nth(clist *l, size_t n);

extern clist *clist_insert_sorted(clist *l, void *data,
			   int (*compar)(const void *, const void *, void *),
			   void *user_private);
extern clist *clist_sort(clist *l,
			 int (*compar)(const void *, const void *, void *),
			 void *user_private);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_CLIST_H__ */
