/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "libtest.h"                    // for parse_script_str, etc
#include <ccoin/core.h>                 // for bp_tx, bp_txin, etc
#include <ccoin/cstr.h>                 // for cstr_free, cstring
#include <ccoin/hexcode.h>              // for hex2str
#include <ccoin/script.h>               // for bp_script_verify, etc

#include <jansson.h>

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, bool, false
#include <stdio.h>                      // for fprintf, stderr
#include <stdlib.h>                     // for NULL, free
#include <string.h>                     // for strcmp, strtok, strlen


struct bp_tx BuildCreditingTransaction(struct cstring* scriptPubKey, int64_t nValue)
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
    txoutCredit->nValue = nValue;
    parr_add(txCredit.vout, txoutCredit);
    bp_tx_calc_sha256(&txCredit);

    return txCredit;
}

struct bp_tx BuildSpendingTransaction(struct cstring* scriptSig,
    parr* scriptWitness,
    struct bp_tx* txCredit)
{
    struct bp_tx txSpend;
    bp_tx_init(&txSpend);
    txSpend.nVersion = 1;
    txSpend.nLockTime = 0;
    txSpend.vin = parr_new(0, bp_txin_freep);
    txSpend.vout = parr_new(0, bp_txout_freep);

    struct bp_txin* txinSpend = calloc(1, sizeof(struct bp_txin));
    bp_txin_init(txinSpend);
    txinSpend->scriptWitness = scriptWitness;
    bu256_copy(&txinSpend->prevout.hash, &txCredit->sha256);
    txinSpend->prevout.n = 0;
    txinSpend->scriptSig = cstr_new_buf(scriptSig->str, scriptSig->len);
    txinSpend->nSequence = SEQUENCE_FINAL;
    parr_add(txSpend.vin, txinSpend);

    struct bp_txout* txoutSpend = calloc(1, sizeof(struct bp_txout));
    bp_txout_init(txoutSpend);
    txoutSpend->scriptPubKey = cstr_new(NULL);
    struct bp_txout* txoutCredit = parr_idx(txCredit->vout, 0);
    txoutSpend->nValue = txoutCredit->nValue;
    parr_add(txSpend.vout, txoutSpend);

    bp_tx_free(txCredit);
    return txSpend;
}

static void test_script(bool is_valid, cstring* scriptSig, cstring* scriptPubKey,
    parr* scriptWitness, unsigned int idx, const char* scriptSigString,
    const char* scriptPubKeyString, const unsigned int test_flags,int64_t nValue)
{
    struct bp_tx tx = BuildCreditingTransaction(scriptPubKey, nValue);
    tx = BuildSpendingTransaction(scriptSig, scriptWitness, &tx);

    bool rc;
    rc = bp_script_verify(
        scriptSig, scriptPubKey, &scriptWitness, &tx, 0, test_flags, SIGHASH_NONE, nValue);

    if (rc != is_valid) {
        fprintf(stderr, "script: %sis_valid test %u failed\n"
                        "script: [\"%s\", \"%s\"]\n",
            is_valid ? "" : "!", idx, scriptSigString, scriptPubKeyString);
        assert(rc == is_valid);
    }

    bp_tx_free(&tx);
}

static void runtest(const char *json_base_fn)
{
    char* json_fn = test_filename(json_base_fn);
    json_t* tests = read_json(json_fn);
    assert(tests != NULL);
    assert(json_is_array(tests));
    static unsigned int verify_flags;
    bool is_valid;

    unsigned int idx;
    for (idx = 0; idx < json_array_size(tests); idx++) {
        json_t* test = json_array_get(tests, idx);
        assert(json_is_array(test));
        parr* scriptWitness = parr_new(0, buffer_freep);
        int64_t nValue = 0;
        unsigned int pos = 0;
        if ((json_array_size(test) > 0) &&
            (json_is_array(json_array_get(test, pos)))) {
            json_t* witness_data = json_array_get(test, pos);
            unsigned int i;
            for (i = 0; i < json_array_size(witness_data) - 1; i++) {
                cstring* witness = hex2str(json_string_value(json_array_get(witness_data, i)));
                if (!witness)
                    witness = cstr_new_sz(0);
                parr_add(scriptWitness, buffer_copy(witness->str, witness->len));
                cstr_free(witness, true);
            }
            nValue = json_number_value(json_array_get(witness_data, i)) * COIN;
            pos++;
        }

        // Allow size > 3; extra stuff ignored (useful for comments)
        if (json_array_size(test) < 4 + pos) {
            if (json_array_size(test) != 1) {
                fprintf(stderr, "script: Bad test %u\n", idx);
            }
            parr_free(scriptWitness, true);
            continue;
        }

        const char* scriptSigString =
				json_string_value(json_array_get(test, pos++));
		assert(scriptSigString != NULL);
        cstring* scriptSig = parse_script_str(scriptSigString);
        assert(scriptSig != NULL);

        const char *scriptPubKeyString =
				json_string_value(json_array_get(test, pos++));
        assert(scriptPubKeyString != NULL);
        cstring* scriptPubKey = parse_script_str(scriptPubKeyString);
        assert(scriptPubKey != NULL);

        verify_flags = SCRIPT_VERIFY_NONE;

        const char *json_flags = json_string_value(json_array_get(test, pos++));
        if (strlen(json_flags) > 0) {
            const char* json_flag = strtok((char*)json_flags, ",");

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
                else if (strcmp(json_flag, "WITNESS") == 0)
                    verify_flags |= SCRIPT_VERIFY_WITNESS;
                else if (strcmp(json_flag, "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM") == 0)
                    verify_flags |= SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM;
                else if (strcmp(json_flag, "MINIMALIF") == 0)
                    verify_flags |= SCRIPT_VERIFY_MINIMALIF;
                else if (strcmp(json_flag, "NULLFAIL") == 0)
                    verify_flags |= SCRIPT_VERIFY_NULLFAIL;
                else if (strcmp(json_flag, "WITNESS_PUBKEYTYPE") == 0)
                    verify_flags |= SCRIPT_VERIFY_WITNESS_PUBKEYTYPE;
                json_flag = strtok(NULL, ",");
            } while (json_flag);
        }

        const char* scriptError = json_string_value(json_array_get(test, pos++));

        is_valid = strcmp(scriptError, "OK") == 0 ? true : false;
        test_script(is_valid, scriptSig, scriptPubKey, scriptWitness, idx,
            scriptSigString, scriptPubKeyString, verify_flags, nValue);

        cstr_free(scriptSig, true);
        cstr_free(scriptPubKey, true);
    }

    json_decref(tests);
    free(json_fn);
}

int main (int argc, char *argv[])
{
    runtest("data/script_tests.json");
    return 0;
}
