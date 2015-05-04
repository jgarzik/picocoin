/* Copyright 2015 BitPay, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include "libtest.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <ccoin/hashtab.h>
#include <ccoin/util.h>

static void test_basics(void)
{
	struct bp_hashtab *ht;

	ht = bp_hashtab_new_ext(czstr_hash, czstr_equal, free, free);
	assert(ht != NULL);

	bp_hashtab_ref(ht);

	assert(bp_hashtab_size(ht) == 0);

	bp_hashtab_put(ht, strdup("name"), strdup("john"));

	assert(bp_hashtab_size(ht) == 1);

	char *lr = bp_hashtab_get(ht, "name");
	assert(lr != NULL);
	assert(strcmp(lr, "john") == 0);

	void *ret_key = NULL;
	void *ret_value = NULL;
	bool rc = bp_hashtab_get_ext(ht, "name", &ret_key, &ret_value);
	assert(rc == true);
	assert(ret_key != NULL);
	assert(ret_value != NULL);
	assert(strcmp(ret_key, "name") == 0);
	assert(strcmp(ret_value, "john") == 0);

	rc = bp_hashtab_get_ext(ht, "name", NULL, NULL);
	assert(rc == true);

	void *dummy = bp_hashtab_get(ht, "dummy");
	assert(dummy == NULL);

	assert(bp_hashtab_size(ht) == 1);

	rc = bp_hashtab_clear(ht);
	assert(rc == true);

	assert(bp_hashtab_size(ht) == 0);

	bp_hashtab_unref(ht);
	bp_hashtab_unref(ht);
}

struct iter_info {
	unsigned int count;
};

static void test_generate_iter(void *key_, void *val_, void *priv)
{
	char *key = key_;
	char *value = val_;
	struct iter_info *ii = priv;

	ii->count++;

	(void) key;
	(void) value;
}

static void test_generate(void)
{
	struct bp_hashtab *ht;

	ht = bp_hashtab_new_ext(czstr_hash, czstr_equal, free, free);
	assert(ht != NULL);

	const int n_values = 100000;
	unsigned int i;
	char s[32];

	for (i = 0; i < n_values; i++) {
		sprintf(s, "%d", i);
		char *key = strdup(s);
		char *value = strdup(s);

		bool rc = bp_hashtab_put(ht, key, value);
		assert(rc == true);
	}

	assert(bp_hashtab_size(ht) == n_values);

	for (i = 0; i < n_values; i++) {
		sprintf(s, "%d", i);

		char *value = bp_hashtab_get(ht, s);
		assert(value != NULL);
		assert(strcmp(s, value) == 0);
	}

	assert(bp_hashtab_size(ht) == n_values);

	void *dummy = bp_hashtab_get(ht, "dummy");
	assert(dummy == NULL);

	struct iter_info ii = {};
	bp_hashtab_iter(ht, test_generate_iter, &ii);
	assert(ii.count == n_values);

	bp_hashtab_unref(ht);
}

int main (int argc, char *argv[])
{
	test_basics();
	test_generate();
	return 0;
}

