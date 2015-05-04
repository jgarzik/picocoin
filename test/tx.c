/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <jansson.h>
#include <ccoin/message.h>
#include <ccoin/mbr.h>
#include <ccoin/util.h>
#include "libtest.h"

static void runtest(const char *json_fn_base, const char *ser_fn_base)
{
	char *fn = test_filename(json_fn_base);
	json_t *meta = read_json(fn);
	assert(json_is_object(meta));

	char *ser_fn = test_filename(ser_fn_base);

	void *data = NULL;
	size_t data_len = 0;

	bool rc = bu_read_file(ser_fn, &data, &data_len, 100 * 1024 * 1024);
	assert(rc);

	const char *hashstr = json_string_value(json_object_get(meta, "hash"));
	assert(hashstr != NULL);

	unsigned int size = json_integer_value(json_object_get(meta, "size"));
	assert(data_len == size);

	struct bp_tx tx;
	bp_tx_init(&tx);

	struct const_buffer buf = { data, data_len };

	rc = deser_bp_tx(&tx, &buf);
	assert(rc);

	cstring *gs = cstr_new_sz(10000);
	ser_bp_tx(gs, &tx);

	if (gs->len != data_len) {
		fprintf(stderr, "gs->len %ld, data_len %lu\n",
			(long)gs->len, data_len);
		assert(gs->len == data_len);
	}
	assert(memcmp(gs->str, data, data_len) == 0);

	bp_tx_calc_sha256(&tx);

	char hexstr[BU256_STRSZ];
	bu256_hex(hexstr, &tx.sha256);

	if (strcmp(hexstr, hashstr)) {
		fprintf(stderr, "tx: wanted hash %s,\n    got    hash %s\n",
			hashstr, hexstr);
		assert(!strcmp(hexstr, hashstr));
	}

	assert(tx.vin->len == 1);
	assert(tx.vout->len == 2);

	struct bp_tx tx_copy;
	bp_tx_init(&tx_copy);

	bp_tx_copy(&tx_copy, &tx);
	bp_tx_calc_sha256(&tx_copy);
	assert(bu256_equal(&tx_copy.sha256, &tx.sha256) == true);

	bp_tx_free(&tx);
	bp_tx_free(&tx_copy);
	cstr_free(gs, true);
	free(data);
	free(fn);
	free(ser_fn);
	json_decref(meta);
}

int main (int argc, char *argv[])
{
	runtest("tx3e0dc3da.json", "tx3e0dc3da.ser");

	return 0;
}
