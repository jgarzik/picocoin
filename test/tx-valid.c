
#include "picocoin-config.h"

#include <assert.h>
#include <jansson.h>
#include <ccoin/core.h>
#include <ccoin/hexcode.h>
#include <ccoin/buint.h>
#include "libtest.h"

static guint input_hash(gconstpointer key_)
{
	const struct bp_outpt *key = key_;

	return (guint) key->hash.dword[2];
}

static gboolean input_equal(gconstpointer a_, gconstpointer b_)
{
	const struct bp_outpt *a = a_;
	const struct bp_outpt *b = b_;

	return ((a->n == b->n) &&
		bu256_equal(&a->hash, &b->hash));
}

static void input_value_free(gpointer v)
{
	g_string_free(v, TRUE);
}

static void test_tx_valid(bool is_valid, GHashTable *input_map,
			  GString *tx_ser, bool enforce_p2sh)
{
	// FIXME
}

static void runtest(bool is_valid, const char *basefn)
{
	char *fn = test_filename(basefn);
	json_t *tests = read_json(fn);
	assert(json_is_array(tests));

	GHashTable *input_map = g_hash_table_new_full(
		input_hash, input_equal,
		g_free, input_value_free);

	unsigned int idx;
	for (idx = 0; idx < json_array_size(tests); idx++) {
		json_t *test = json_array_get(tests, idx);

		if (!json_is_array(json_array_get(test, 0)))
			continue;			/* comments */

		assert(json_is_array(test));
		assert(json_array_size(test) == 3);
		assert(json_is_string(json_array_get(test, 1)));
		assert(json_is_boolean(json_array_get(test, 2)));

		json_t *inputs = json_array_get(test, 0);
		assert(json_is_array(inputs));

		g_hash_table_remove_all(input_map);

		unsigned int i;
		for (i = 0; i < json_array_size(inputs); i++) {
			json_t *input = json_array_get(inputs, i);
			assert(json_is_array(input));

			const char *prev_hashstr =
				json_string_value(json_array_get(input, 0));
			int prev_n =
				json_integer_value(json_array_get(input, 1));
			const char *prev_pubkey_enc =
				json_string_value(json_array_get(input, 2));

			assert(prev_hashstr != NULL);
			assert(json_is_integer(json_array_get(input, 1)));
			assert(prev_pubkey_enc != NULL);

			GString *prev_rawhash = hex2str(prev_hashstr);
			assert(prev_rawhash->len == sizeof(bu256_t));

			struct bp_outpt *outpt;
			outpt = malloc(sizeof(*outpt));
			memcpy(&outpt->hash, prev_rawhash->str,
			       sizeof(outpt->hash));
			outpt->n = prev_n;

			GString *script = parse_script_str(prev_pubkey_enc);
			assert(script != NULL);

			g_hash_table_insert(input_map, outpt, script);

			g_string_free(prev_rawhash, TRUE);
		}

		const char *tx_hexser =
			json_string_value(json_array_get(test, 1));
		assert(tx_hexser != NULL);

		bool enforce_p2sh = json_is_true(json_array_get(test, 2));

		GString *tx_ser = hex2str(tx_hexser);
		assert(tx_ser != NULL);

		test_tx_valid(is_valid, input_map, tx_ser, enforce_p2sh);

		g_string_free(tx_ser, TRUE);
	}

	g_hash_table_unref(input_map);
	json_decref(tests);
	free(fn);
}

int main (int argc, char *argv[])
{
	runtest(true, "tx_valid.json");
	return 0;
}

