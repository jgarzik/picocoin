/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <assert.h>
#include <string.h>
#include <ccoin/parr.h>

static void test_basic(void)
{
	parr *pa;
	bool rc;

	pa = parr_new(0, free);
	assert(pa != NULL);
	assert(pa->data != NULL);
	assert(pa->len == 0);
	assert(pa->alloc > 0);

	rc = parr_add(pa, strdup("foo"));
	assert(rc == true);
	assert(pa->len == 1);

	rc = parr_add(pa, strdup("bar"));
	assert(rc == true);
	assert(pa->len == 2);

	char *baz_str = strdup("baz");
	rc = parr_add(pa, baz_str);
	assert(rc == true);
	assert(pa->len == 3);

	assert(parr_find(pa, baz_str) == 2);
	assert(parr_find(pa, "dummy") == -1);

	assert(strcmp(parr_idx(pa, 0), "foo") == 0);
	assert(strcmp(parr_idx(pa, 1), "bar") == 0);
	assert(strcmp(parr_idx(pa, 2), "baz") == 0);

	rc = parr_remove(pa, baz_str);
	assert(rc == true);
	assert(pa->len == 2);

	assert(strcmp(parr_idx(pa, 0), "foo") == 0);
	assert(strcmp(parr_idx(pa, 1), "bar") == 0);

	parr_remove_idx(pa, 0);

	assert(pa->len == 1);

	assert(strcmp(parr_idx(pa, 0), "bar") == 0);

	parr_free(pa, true);
}

static void test_resize(void)
{
	parr *pa;
	bool rc;

	pa = parr_new(0, free);
	assert(pa != NULL);
	assert(pa->data != NULL);
	assert(pa->len == 0);
	assert(pa->alloc > 0);

	rc = parr_add(pa, strdup("foo"));
	rc = parr_add(pa, strdup("bar"));
	rc = parr_add(pa, strdup("baz"));

	rc = parr_resize(pa, 3);
	assert(rc == true);

	rc = parr_resize(pa, 2);
	assert(rc == true);

	assert(pa->len == 2);

	assert(strcmp(parr_idx(pa, 0), "foo") == 0);
	assert(strcmp(parr_idx(pa, 1), "bar") == 0);

	rc = parr_resize(pa, 10);
	assert(rc == true);

	parr_free(pa, true);
}

int main (int argc, char *argv[])
{
	test_basic();
	test_resize();
	return 0;
}

