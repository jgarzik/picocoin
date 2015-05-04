/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include <ccoin/parr.h>

parr *parr_new(size_t res, void (*free_f)(void *))
{
	parr *pa = calloc(1, sizeof(parr));
	if (!pa)
		return NULL;

	pa->alloc = 8;
	while (pa->alloc < res)
		pa->alloc *= 2;

	pa->elem_free_f = free_f;
	pa->data = malloc(pa->alloc * sizeof(void *));
	if (!pa->data) {
		free(pa);
		return NULL;
	}

	return pa;
}

static void parr_free_data(parr *pa)
{
	if (!pa->data)
		return;

	if (pa->elem_free_f) {
		unsigned int i;
		for (i = 0; i < pa->len; i++)
			if (pa->data[i]) {
				pa->elem_free_f(pa->data[i]);
				pa->data[i] = NULL;
			}
	}

	free(pa->data);
	pa->data = NULL;
	pa->alloc = 0;
	pa->len = 0;
}

void parr_free(parr *pa, bool free_array)
{
	if (!pa)
		return;

	if (free_array)
		parr_free_data(pa);

	memset(pa, 0, sizeof(*pa));
	free(pa);
}

static bool parr_grow(parr *pa, size_t min_sz)
{
	size_t new_alloc = pa->alloc;
	while (new_alloc < min_sz)
		new_alloc *= 2;

	if (pa->alloc == new_alloc)
		return true;

	void *new_data = realloc(pa->data, new_alloc * sizeof(void *));
	if (!new_data)
		return false;

	pa->data = new_data;
	pa->alloc = new_alloc;
	return true;
}

ssize_t parr_find(parr *pa, void *data)
{
	if (pa && pa->len) {
		size_t i;
		for (i = 0; i < pa->len; i++)
			if (pa->data[i] == data)
				return (ssize_t) i;
	}

	return -1;
}

bool parr_add(parr *pa, void *data)
{
	if (pa->len == pa->alloc)
		if (!parr_grow(pa, pa->len + 1))
			return false;

	pa->data[pa->len] = data;
	pa->len++;
	return true;
}

void parr_remove_range(parr *pa, size_t pos, size_t len)
{
	if (!pa || ((pos+len) > pa->len))
		return;

	if (pa->elem_free_f) {
		unsigned int i, count;
		for (i = pos, count = 0; count < len; i++, count++)
			pa->elem_free_f(pa->data[i]);
	}

	memmove(&pa->data[pos], &pa->data[pos + len],
		(pa->len - pos - len) * sizeof(void *));
	pa->len -= len;
}

void parr_remove_idx(parr *pa, size_t pos)
{
	parr_remove_range(pa, pos, 1);
}

bool parr_remove(parr *pa, void *data)
{
	ssize_t idx = parr_find(pa, data);
	if (idx < 0)
		return false;

	parr_remove_idx(pa, idx);
	return true;
}

bool parr_resize(parr *pa, size_t newsz)
{
	unsigned int i;

	// same size
	if (newsz == pa->len)
		return true;

	// truncate
	else if (newsz < pa->len) {
		size_t del_count = pa->len - newsz;

		for (i = (pa->len - del_count); i < pa->len; i++) {
			if (pa->elem_free_f)
				pa->elem_free_f(pa->data[i]);
			pa->data[i] = NULL;
		}

		pa->len = newsz;
		return true;
	}

	// last possibility: grow
	if (!parr_grow(pa, newsz))
		return false;

	// set new elements to NULL
	for (i = pa->len; i < newsz; i++)
		pa->data[i] = NULL;

	pa->len = newsz;
	return true;
}

