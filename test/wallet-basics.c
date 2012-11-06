
#include "picocoin-config.h"

#include <assert.h>
#include <jansson.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/buffer.h>
#include <ccoin/buint.h>
#include <ccoin/hexcode.h>
#include <ccoin/key.h>
#include <ccoin/addr_match.h>
#include "libtest.h"

static void load_json_key(json_t *wallet, struct bp_key *key)
{
	json_t *keys_a = json_object_get(wallet, "keys");
	assert(json_is_array(keys_a));

	json_t *key_o = json_array_get(keys_a, 0);
	assert(json_is_object(key_o));

	const char *privkey_str = json_string_value(json_object_get(key_o, "privkey"));
	assert(privkey_str != NULL);

	char rawbuf[strlen(privkey_str)];
	size_t buf_len = 0;

	assert(decode_hex(rawbuf, sizeof(rawbuf), privkey_str, &buf_len) == true);

	assert(bp_privkey_set(key, rawbuf, buf_len) == true);
}

static void runtest(const char *json_base_fn, const char *ser_in_fn,
		    const char *block_in_hash)
{
	/* read wallet data */
	char *json_fn = test_filename(json_base_fn);
	json_t *wallet = read_json(json_fn);
	assert(wallet != NULL);

	/* read block data containing incoming payment */
	char *fn = test_filename(ser_in_fn);
	void *data;
	size_t data_len;
	assert(bu_read_file(fn, &data, &data_len, 1 * 1024 * 1024) == true);

	struct bp_block block_in;
	bp_block_init(&block_in);
	struct const_buffer buf = { data, data_len };

	assert(deser_bp_block(&block_in, &buf) == true);
	bp_block_calc_sha256(&block_in);

	/* verify block-in data matches expected block-in hash */
	bu256_t check_hash;
	assert(hex_bu256(&check_hash, block_in_hash) == true);

	assert(bu256_equal(&block_in.sha256, &check_hash) == true);

	/* load key that has received an incoming payment */
	struct bp_key key;
	assert(bp_key_init(&key) == true);

	load_json_key(wallet, &key);

	/* load key into keyset */
	struct bp_keyset ks;
	bpks_init(&ks);

	assert(bpks_add(&ks, &key) == true);

	/* find key matches in block */
	GPtrArray *matches;
	matches = bp_block_match(&block_in, &ks);
	assert(matches != NULL);
	assert(matches->len == 1);

	/* release resources */
	g_ptr_array_free(matches, TRUE);
	bpks_free(&ks);
	bp_key_free(&key);
	bp_block_free(&block_in);
	json_decref(wallet);
}

int main (int argc, char *argv[])
{
	runtest("wallet-basics.json", "tn_blk35133.ser",
	    "00000000003bf8f8f24e0c5f592a38bb7c18352745ef7192f1a576d855fd6b2d");

	return 0;
}
