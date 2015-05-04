/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdlib.h>
#include <string.h>
#include <ccoin/clist.h>

void clist_free_ext(clist *l, void (*free_f)(void *))
{
	while (l) {
		clist *tmp = l;
		l = l->next;

		if (free_f)
			free_f(tmp->data);

		memset(tmp, 0, sizeof(*tmp));
		free(tmp);
	}
}

size_t clist_length(clist *l)
{
	size_t count = 0;

	while (l) {
		count++;

		l = l->next;
	}

	return count;
}

clist *clist_last(clist *l)
{
	if (l)
		while (l->next)
			l = l->next;

	return l;
}

clist *clist_append(clist *l, void *buf)
{
	clist *node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->data = buf;

	if (!l)
		return node;

	clist *last = clist_last(l);
	node->prev = last;
	if (last)
		last->next = node;

	return l;
}

clist *clist_prepend(clist *l, void *buf)
{
	clist *node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->data = buf;
	node->next = l;
	if (l)
		l->prev = node;

	return node;
}

clist *clist_delete(clist *l, clist *link)
{
	if (!l)
		return NULL;
	if (l == link) {
		if (l->prev)
			l = l->prev;
		else
			l = l->next;
	}
	if (link->prev)
		link->prev->next = link->next;
	if (link->next)
		link->next->prev = link->prev;

	memset(link, 0, sizeof(*link));
	free(link);

	return l;
}

clist *clist_nth(clist *l, size_t n)
{
	while (l && (n > 0)) {
		l = l->next;
		n--;
	}

	return l;
}

clist *clist_insert_sorted(clist *l, void *data,
			   int (*compar)(const void *, const void *, void *),
			   void *user_priv)
{
	clist *node = calloc(1, sizeof(*node));
	if (!node)
		return NULL;

	node->data = data;

	// empty list; no need to sort
	if (!l)
		return node;

	// find insertion point
	clist *tmp = l;
	clist *last = NULL;
	while (tmp && compar(data, tmp->data, user_priv) > 0) {
		last = tmp;
		tmp = tmp->next;
	}

	// append at list end?
	if (!tmp) {
		last->next = node;
		node->prev = last;
	}

	// insert
	else {
		node->next = tmp;
		node->prev = tmp->prev;
		tmp->prev = node;
		if (node->prev)
			node->prev->next = node;

		while (l->prev)
			l = l->prev;
	}
	return l;
}

clist *clist_sort(clist *l,
		  int (*compar)(const void *, const void *, void *),
		  void *user_priv)
{
	clist *new_l = NULL;

	while (l) {
		new_l = clist_insert_sorted(new_l, l->data, compar, user_priv);

		l = l->next;
	}

	clist_free(l);

	return new_l;
}

