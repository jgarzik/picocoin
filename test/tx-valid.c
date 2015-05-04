
#include "picocoin-config.h"

#include <assert.h>
#include <jansson.h>
#include <ccoin/core.h>
#include <ccoin/hexcode.h>
#include <ccoin/buint.h>
#include <ccoin/script.h>
#include <ccoin/hashtab.h>
#include <ccoin/compat.h>		/* for parr_new */
#include "libtest.h"

parr *comments = NULL;

static unsigned long input_hash(const void *key_)
{
	const struct bp_outpt *key = key_;

	return key->hash.dword[4];
}

static bool input_equal(const void *a, const void *b)
{
	return bp_outpt_equal(a, b);
}

static void input_value_free(void *v)
{
	cstr_free(v, true);
}

static void dump_comments(void)
{
	unsigned int i;
	for (i = 0; i < comments->len; i++) {
		fprintf(stderr, "tx-valid cmt: %s\n",
			(char *)parr_idx(comments, i));
	}
}

static void test_tx_valid(bool is_valid, struct bp_hashtab *input_map,
			  cstring *tx_ser, bool enforce_p2sh)
{
	struct bp_tx tx;

	bp_tx_init(&tx);

	struct const_buffer buf = { tx_ser->str, tx_ser->len };
	assert(deser_bp_tx(&tx, &buf) == true);

	if (is_valid) {
		/* checking for valid tx; !bp_tx_valid implies test fail */
		assert(bp_tx_valid(&tx) == true);
	} else {
		/* checking for invalid tx; bp_tx_valid==false implies test
		 * succeeded; no more work to do; bp_tx_valid==true
		 * implies the test will detect the invalid condition
		 * further down in the code
		 */
		if (bp_tx_valid(&tx) == false)
			goto out;
	}

	bp_tx_calc_sha256(&tx);

	unsigned int i;
	for (i = 0; i < tx.vin->len; i++) {
		struct bp_txin *txin;

		txin = parr_idx(tx.vin, i);
		assert(txin != NULL);

		cstring *scriptPubKey = bp_hashtab_get(input_map,
						       &txin->prevout);
		if (scriptPubKey == NULL) {
			if (!is_valid) {
				/* if testing tx_invalid.json, missing input
				 * is invalid, and therefore correct
				 */
				continue;
			}

			char tx_hexstr[BU256_STRSZ], hexstr[BU256_STRSZ];
			bu256_hex(tx_hexstr, &tx.sha256);
			bu256_hex(hexstr, &txin->prevout.hash);
			dump_comments();
			fprintf(stderr,
			"tx-valid: TX %s\n"
			"tx-valid: prevout (%s, %u) not found\n",
				tx_hexstr, hexstr, txin->prevout.n);

			assert(scriptPubKey != NULL);
		}

		bool rc = bp_script_verify(txin->scriptSig, scriptPubKey,
					&tx, i,
					enforce_p2sh ? SCRIPT_VERIFY_P2SH :
					SCRIPT_VERIFY_NONE, 0);
		if (rc != is_valid) {
			char tx_hexstr[BU256_STRSZ];
			bu256_hex(tx_hexstr, &tx.sha256);
			dump_comments();
			fprintf(stderr,
			"tx-valid: TX %s\n"
			"tx-valid: txin %u script verification failed\n",
				tx_hexstr, i);

			assert(rc == is_valid);
		}
	}

out:
	bp_tx_free(&tx);
}

static void runtest(bool is_valid, const char *basefn)
{
	char *fn = test_filename(basefn);
	json_t *tests = read_json(fn);
	assert(json_is_array(tests));

	struct bp_hashtab *input_map = bp_hashtab_new_ext(
		input_hash, input_equal,
		free, input_value_free);

	comments = parr_new(8, free);

	unsigned int idx;
	for (idx = 0; idx < json_array_size(tests); idx++) {
		json_t *test = json_array_get(tests, idx);

		if (!json_is_array(json_array_get(test, 0))) {
			const char *cmt =
				json_string_value(json_array_get(test, 0));
			if (cmt)
				parr_add(comments, strdup(cmt));
			continue;			/* comments */
		}

		assert(json_is_array(test));
		assert(json_array_size(test) == 3);
		assert(json_is_string(json_array_get(test, 1)));
		assert(json_is_boolean(json_array_get(test, 2)));

		json_t *inputs = json_array_get(test, 0);
		assert(json_is_array(inputs));

		bp_hashtab_clear(input_map);

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

			struct bp_outpt *outpt;
			outpt = malloc(sizeof(*outpt));
			hex_bu256(&outpt->hash, prev_hashstr);
			outpt->n = prev_n;

			cstring *script = parse_script_str(prev_pubkey_enc);
			assert(script != NULL);

			bp_hashtab_put(input_map, outpt, script);
		}

		const char *tx_hexser =
			json_string_value(json_array_get(test, 1));
		assert(tx_hexser != NULL);

		bool enforce_p2sh = json_is_true(json_array_get(test, 2));

		cstring *tx_ser = hex2str(tx_hexser);
		assert(tx_ser != NULL);

		test_tx_valid(is_valid, input_map, tx_ser, enforce_p2sh);

		cstr_free(tx_ser, true);

		if (comments->len > 0) {
			parr_free(comments, true);
			comments = parr_new(8, free);
		}
	}

	parr_free(comments, true);
	comments = NULL;

	bp_hashtab_unref(input_map);
	json_decref(tests);
	free(fn);
}

int main (int argc, char *argv[])
{
	runtest(true, "tx_valid.json");
	runtest(false, "tx_invalid.json");
	return 0;
}

