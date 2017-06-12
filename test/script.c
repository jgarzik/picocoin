
#include "picocoin-config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <jansson.h>
#include <ccoin/script.h>
#include <ccoin/core.h>
#include "libtest.h"

struct bp_tx BuildCreditingTransaction(struct cstring *scriptPubKey)
{
    struct bp_tx txCredit;
    bp_tx_init(&txCredit);
    txCredit.nVersion = 1;
    txCredit.nLockTime = 0;
    txCredit.vin = parr_new(0, bp_txin_freep);
    txCredit.vout = parr_new(0, bp_txout_freep);

    struct bp_txin* txinCredit = calloc(1, sizeof(struct bp_txin));
    bp_txin_init(txinCredit);
    txinCredit->prevout.n = (uint32_t)-1;
    bu256_set_u64(&txinCredit->prevout.hash, 0);
    txinCredit->scriptSig = cstr_new(NULL);
    cstr_append_c(txinCredit->scriptSig, 0);
    cstr_append_c(txinCredit->scriptSig, 0);
    txinCredit->nSequence = SEQUENCE_FINAL;
    parr_add(txCredit.vin, txinCredit);

    struct bp_txout *txoutCredit = calloc(1, sizeof(struct bp_txout));
    bp_txout_init(txoutCredit);
    txoutCredit->scriptPubKey = cstr_new_buf(scriptPubKey->str, scriptPubKey->len);
    txoutCredit->nValue = (uint64_t) 0;
    parr_add(txCredit.vout, txoutCredit);
    bp_tx_calc_sha256(&txCredit);

    return txCredit;
}

struct bp_tx BuildSpendingTransaction(struct cstring* scriptSig, struct bp_tx* txCredit)
{
    struct bp_tx txSpend;
    bp_tx_init(&txSpend);
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin = parr_new(0, bp_txin_freep);
    txSpend.vout = parr_new(0, bp_txout_freep);

    struct bp_txin* txinSpend = calloc(1, sizeof(struct bp_txin));
    bp_txin_init(txinSpend);
    bu256_copy(&txinSpend->prevout.hash, &txCredit->sha256);
    txinSpend->prevout.n = 0;
    txinSpend->scriptSig = cstr_new_buf(scriptSig->str, scriptSig->len);
    txinSpend->nSequence = SEQUENCE_FINAL;
    parr_add(txSpend.vin, txinSpend);

    struct bp_txout *txoutSpend = calloc(1, sizeof(struct bp_txout));
    bp_txout_init(txoutSpend);
    txoutSpend->scriptPubKey = cstr_new(NULL); //
    txoutSpend->nValue =(uint64_t) 0;
    parr_add(txSpend.vout, txoutSpend);

    bp_tx_free(txCredit);
    return txSpend;
}

static void test_script(bool is_valid, cstring* scriptSig,
                        cstring* scriptPubKey, unsigned int idx,
                        const char* scriptSigEnc, const char* scriptPubKeyEnc,
                        const unsigned int test_flags)
{
    struct bp_tx tx = BuildCreditingTransaction(scriptPubKey);
    tx = BuildSpendingTransaction(scriptSig, &tx);

    bool rc;
    rc = bp_script_verify(scriptSig, scriptPubKey, &tx, 0, test_flags, SIGHASH_NONE);

    if (rc != is_valid) {
        fprintf(stderr, "script: %sis_valid test %u failed\n"
                        "script: [\"%s\", \"%s\"]\n",
            is_valid ? "" : "!", idx, scriptSigEnc, scriptPubKeyEnc);
        assert(rc == is_valid);
    }

    bp_tx_free(&tx);
}

static void runtest(const char *basefn)
{
	char *fn = test_filename(basefn);
	json_t *tests = read_json(fn);
	assert(json_is_array(tests));
	static unsigned int verify_flags;
	bool is_valid;

	unsigned int idx;
	for (idx = 0; idx < json_array_size(tests); idx++) {
		json_t *test = json_array_get(tests, idx);
		assert(json_is_array(test));
		unsigned int pos = 0;
		if ( json_array_size(test) > 1) {
			const char *scriptSigEnc =
				json_string_value(json_array_get(test, pos++));
			const char *scriptPubKeyEnc =
				json_string_value(json_array_get(test, pos++));
			assert(scriptSigEnc != NULL);
			assert(scriptPubKeyEnc != NULL);

			cstring *scriptSig = parse_script_str(scriptSigEnc);

			cstring *scriptPubKey = parse_script_str(scriptPubKeyEnc);
			assert(scriptSig != NULL);
			assert(scriptPubKey != NULL);

			verify_flags = SCRIPT_VERIFY_NONE;

			const char *json_flags = json_string_value(json_array_get(test, pos++));

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
					else if (strcmp(json_flag, "CHECKSEQUENCEVERIFY") == 0)
						verify_flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
					json_flag = strtok(NULL, ",");
				} while (json_flag);
			}

			const char *scriptError =
				json_string_value(json_array_get(test, 3));

			is_valid = strcmp(scriptError, "OK") == 0 ? true : false;
			test_script(is_valid, scriptSig, scriptPubKey,
				    idx, scriptSigEnc, scriptPubKeyEnc, verify_flags);

			cstr_free(scriptSig, true);
			cstr_free(scriptPubKey, true);
		}
	}

	json_decref(tests);
	free(fn);
}

int main (int argc, char *argv[])
{
	runtest("script_tests.json");
	return 0;
}
