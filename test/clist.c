/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <assert.h>
#include <string.h>
#include <ccoin/clist.h>

static int cstr_cmp(const void *a_, const void *b_, void *user_priv)
{
	const char *a = a_;
	const char *b = b_;

	return strcmp(a, b);
}

static void test_basic(void)
{
	clist_free(NULL);
	clist_free_ext(NULL, NULL);

	assert(clist_length(NULL) == 0);
	assert(clist_last(NULL) == NULL);
	assert(clist_nth(NULL, 22) == NULL);

	clist *l = NULL;
	l = clist_append(l, "1");
	l = clist_append(l, "2");
	l = clist_prepend(l, "0");
	assert(clist_length(l) == 3);
	assert(strcmp(clist_nth(l, 0)->data, "0") == 0);
	assert(strcmp(clist_nth(l, 1)->data, "1") == 0);
	assert(strcmp(clist_nth(l, 2)->data, "2") == 0);
	assert(strcmp(clist_last(l)->data, "2") == 0);

	clist *first = clist_nth(l, 0);
	assert(first != NULL);
	l = clist_delete(l, first);

	assert(clist_length(l) == 2);
	assert(strcmp(clist_nth(l, 0)->data, "1") == 0);
	assert(strcmp(clist_nth(l, 1)->data, "2") == 0);

	l = clist_append(l, "0");
	l = clist_sort(l, cstr_cmp, NULL);

	assert(clist_length(l) == 3);
	assert(strcmp(clist_nth(l, 0)->data, "0") == 0);
	assert(strcmp(clist_nth(l, 1)->data, "1") == 0);
	assert(strcmp(clist_nth(l, 2)->data, "2") == 0);

	clist_free(l);
}

int main (int argc, char *argv[])
{
	test_basic();
	return 0;
}

