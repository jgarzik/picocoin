/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include <assert.h>
#include <string.h>
#include <ccoin/cstr.h>

static void test_basic(void)
{
	cstring *s = cstr_new("foo");
	assert(s != NULL);
	assert(s->len == 3);
	assert(strcmp(s->str, "foo") == 0);

	cstr_free(s, true);

	s = cstr_new_sz(200);
	assert(s != NULL);
	assert(s->alloc > 200);
	assert(s->len == 0);

	cstr_free(s, true);

	s = cstr_new_buf("foo", 2);
	assert(s != NULL);
	assert(s->len == 2);
	assert(strcmp(s->str, "fo") == 0);

	cstr_free(s, true);

	s = cstr_new(NULL);
	assert(s != NULL);
	cstr_append_buf(s, "f", 1);
	cstr_append_buf(s, "o", 1);
	cstr_append_buf(s, "o", 1);
	assert(s->len == 3);
	assert(strcmp(s->str, "foo") == 0);

	cstr_free(s, true);

	s = cstr_new("foo");
	assert(s != NULL);

	cstr_resize(s, 2);
	assert(s->len == 2);
	assert(strcmp(s->str, "fo") == 0);

	cstr_resize(s, 4);
	assert(s->len == 4);
	assert(s->alloc > 4);
	memcpy(s->str, "food", 4);
	assert(strcmp(s->str, "food") == 0);

	cstr_free(s, true);

	cstring *s1 = cstr_new("foo");
	cstring *s2 = cstr_new("foo");
	cstring *s3 = cstr_new("bar");

	assert(cstr_equal(s1, s2) == true);
	assert(cstr_equal(s1, s3) == false);
	assert(cstr_equal(s2, s3) == false);
	assert(cstr_equal(s3, s3) == true);

	cstr_free(s1, true);
	cstr_free(s2, true);
	cstr_free(s3, true);
}

int main (int argc, char *argv[])
{
	test_basic();
	return 0;
}

