
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

static void test_tx_valid(bool is_valid, struct bp_hashtab* mapprevOutScriptPubKeys,
    struct bp_hashtab* mapprevOutValues, cstring* tx_ser, const unsigned int test_flags)
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

	bool state = true;
	unsigned int i;
	for (i = 0; i < tx.vin->len; i++) {
		struct bp_txin *txin;

		txin = parr_idx(tx.vin, i);
		assert(txin != NULL);

		cstring* scriptPubKey = bp_hashtab_get(mapprevOutScriptPubKeys, &txin->prevout);
		int64_t* amount = bp_hashtab_get(mapprevOutValues, &txin->prevout);

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

                bool rc = bp_script_verify(txin->scriptSig, scriptPubKey, &txin->scriptWitness,
                                        &tx, i, test_flags, SIGHASH_NONE, *amount);

                state &= rc;

                if (rc != is_valid) {
			char tx_hexstr[BU256_STRSZ];
			bu256_hex(tx_hexstr, &tx.sha256);
			dump_comments();
			fprintf(stderr,
			"tx-valid: TX %s\n"
			"tx-valid: txin %u script verification failed\n",
				tx_hexstr, i);
		}
	}
	assert(state == is_valid);

out:
	bp_tx_free(&tx);
}

static void runtest(bool is_valid, const char *json_base_fn)
{
	char *json_fn = test_filename(json_base_fn);
	json_t *tests = read_json(json_fn);
	assert(tests != NULL);
	assert(json_is_array(tests));

	struct bp_hashtab* mapprevOutScriptPubKeys =
            bp_hashtab_new_ext(input_hash, input_equal, free, input_value_free);
        struct bp_hashtab* mapprevOutValues =
            bp_hashtab_new_ext(input_hash, input_equal, free, free);

        comments = parr_new(8, free);

	unsigned int idx;
	for (idx = 0; idx < json_array_size(tests); idx++) {
		json_t *test = json_array_get(tests, idx);

		assert(json_is_array(test));
		if (!json_is_array(json_array_get(test, 0))) {
			const char *cmt =
				json_string_value(json_array_get(test, 0));
			if (cmt)
				parr_add(comments, strdup(cmt)); /* comments */
		} else {
                        assert(json_array_size(test) == 3);
                        assert(json_is_string(json_array_get(test, 1)));
                        assert(json_is_string(json_array_get(test, 2)));

                        json_t *inputs = json_array_get(test, 0);
                        assert(json_is_array(inputs));
                        static unsigned int verify_flags;

                        bp_hashtab_clear(mapprevOutScriptPubKeys);
                        bp_hashtab_clear(mapprevOutValues);

                        unsigned int inpIdx;
                        for (inpIdx = 0; inpIdx < json_array_size(inputs); inpIdx++) {
                                json_t *input = json_array_get(inputs, inpIdx);
                                assert(json_is_array(input));

                                const char* prev_hashstr =
					json_string_value(json_array_get(input, 0));
                                int prev_n =
					json_integer_value(json_array_get(input, 1));
                                const char* prev_pubkey_enc =
					json_string_value(json_array_get(input, 2));

                                assert(prev_hashstr != NULL);
                                assert(json_is_integer(json_array_get(input, 1)));
                                assert(prev_pubkey_enc != NULL);

                                struct bp_outpt* outpt;
                                outpt = malloc(sizeof(*outpt));
                                hex_bu256(&outpt->hash, prev_hashstr);
                                outpt->n = prev_n;

                                cstring* script = parse_script_str(prev_pubkey_enc);
                                assert(script != NULL);

                                bp_hashtab_put(mapprevOutScriptPubKeys, outpt, script);

                                struct bp_outpt* outpt_amt;
                                outpt_amt = malloc(sizeof(*outpt_amt));
                                hex_bu256(&outpt_amt->hash, prev_hashstr);
                                outpt_amt->n = prev_n;

                                int64_t* amount;
                                amount = malloc(sizeof(*amount));
                                *amount = 0;
                                if (json_array_size(input) >= 4) {
                                        assert(json_is_number(json_array_get(input, 3)));
                                        *amount = json_number_value(json_array_get(input, 3));
                                }
                                bp_hashtab_put(mapprevOutValues, outpt_amt, amount);
                        }

                        const char *tx_hexser =
                                        json_string_value(json_array_get(test, 1));
                        assert(tx_hexser != NULL);

                        verify_flags = SCRIPT_VERIFY_NONE;

                        const char *json_flags = json_string_value(json_array_get(test, 2));

                        if (strlen(json_flags) > 0) {
                                const char* json_flag  = strtok((char *)json_flags, ",");

				do {
					if (strcmp(json_flag, "P2SH") == 0)
                                                verify_flags |= SCRIPT_VERIFY_P2SH;
					else if (strcmp(json_flag, "STRICTENC") == 0)
                                                verify_flags |= SCRIPT_VERIFY_STRICTENC;
					else if (strcmp(json_flag, "DERSIG") == 0)
                                                verify_flags |= SCRIPT_VERIFY_DERSIG;
					else if (strcmp(json_flag, "LOW_S") == 0)
                                                verify_flags |= SCRIPT_VERIFY_LOW_S;
					else if (strcmp(json_flag, "NULLDUMMY") == 0)
                                                verify_flags |= SCRIPT_VERIFY_NULLDUMMY;
					else if (strcmp(json_flag, "SIGPUSHONLY") == 0)
                                                verify_flags |= SCRIPT_VERIFY_SIGPUSHONLY;
					else if (strcmp(json_flag, "MINIMALDATA") == 0)
                                                verify_flags |= SCRIPT_VERIFY_MINIMALDATA;
					else if (strcmp(json_flag, "DISCOURAGE_UPGRADABLE_NOPS") == 0)
                                                verify_flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS;
					else if (strcmp(json_flag, "CLEANSTACK") == 0)
                                                verify_flags |= SCRIPT_VERIFY_CLEANSTACK;
					else if (strcmp(json_flag, "CHECKLOCKTIMEVERIFY") == 0)
                                                verify_flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
					else if (strcmp(json_flag, "CHECKSEQUENCEVERIFY") == 0)
                                                verify_flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
                                        else if (strcmp(json_flag, "WITNESS") == 0)
                                                verify_flags |= SCRIPT_VERIFY_WITNESS;
                                        else if (strcmp(json_flag, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM") == 0)
                                                verify_flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
                                        json_flag = strtok(NULL, ",");
                                } while (json_flag);
                        }

                        cstring *tx_ser = hex2str(tx_hexser);
                        assert(tx_ser != NULL);

                        test_tx_valid(is_valid, mapprevOutScriptPubKeys,
                        mapprevOutValues, tx_ser, verify_flags);

                        cstr_free(tx_ser, true);

                        if (comments->len > 0) {
                                parr_free(comments, true);
				comments = parr_new(8, free);
                        }
		}
        }

	parr_free(comments, true);
	comments = NULL;
        bp_hashtab_unref(mapprevOutScriptPubKeys);
        bp_hashtab_unref(mapprevOutValues);
        json_decref(tests);
	free(json_fn);
}

int main (int argc, char *argv[])
{
	runtest(true, "data/tx_valid.json");
	runtest(false, "data/tx_invalid.json");

        bp_key_static_shutdown();
	return 0;
}
