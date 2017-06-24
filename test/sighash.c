/* Copyright 2017 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include "libtest.h"                    // for read_json, test_filename
#include <ccoin/buffer.h>               // for const_buffer
#include <ccoin/buint.h>                // for bu256_equal, bu256_t, etc
#include <ccoin/core.h>                 // for bp_tx_free, bp_tx_init, etc
#include <ccoin/cstr.h>                 // for cstr_free, cstring
#include <ccoin/hexcode.h>              // for hex2str
#include <ccoin/script.h>               // for bp_tx_sighash

#include <jansson.h>

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true
#include <stdio.h>                      // for NULL
#include <stdlib.h>                     // for free


static void runtest(const char* json_base_fn)
{
    char* json_fn = test_filename(json_base_fn);
    json_t* tests = read_json(json_fn);
    assert(tests != NULL);
    assert(json_is_array(tests));

    size_t n_tests = json_array_size(tests);
    unsigned int idx;
    for (idx = 0; idx < n_tests; idx++) {
        json_t* test = json_array_get(tests, idx);
        assert(json_is_array(test));

        if (json_array_size(test) == 1)
            assert(json_is_string(json_array_get(test, 0)));
        else {
            assert(json_array_size(test) == 5);
            assert(json_is_string(json_array_get(test, 0)));
            assert(json_is_string(json_array_get(test, 1)));
            assert(json_is_integer(json_array_get(test, 2)));
            assert(json_is_integer(json_array_get(test, 3)));
            assert(json_is_string(json_array_get(test, 4)));

            const char *tx_hexser = json_string_value(json_array_get(test, 0));
		    assert(tx_hexser != NULL);
		    cstring *tx_ser = hex2str(tx_hexser);
		    assert(tx_ser != NULL);

            struct bp_tx txTo;
            bp_tx_init(&txTo);
            struct const_buffer buf = { tx_ser->str, tx_ser->len };
            assert(deser_bp_tx(&txTo, &buf) == true);
            assert(bp_tx_valid(&txTo) == true);

            const char *scriptCode_hexser = json_string_value(json_array_get(test, 1));
		    assert(scriptCode_hexser != NULL);
		    cstring *scriptCode = hex2str(scriptCode_hexser);

		    unsigned int nIn = json_integer_value(json_array_get(test, 2));
		    int nHashType = json_integer_value(json_array_get(test, 3));

		    bu256_t sighash;
		    bp_tx_sighash(&sighash, scriptCode, &txTo, nIn, nHashType);

            bu256_t sighash_res;
            hex_bu256(&sighash_res, json_string_value(json_array_get(test, 4)));
            assert(bu256_equal(&sighash, &sighash_res));

            cstr_free(scriptCode, true);
            cstr_free(tx_ser, true);
            bp_tx_free(&txTo);
        }
    }
    json_decref(tests);
    free(json_fn);
}

int main(int argc, char* argv[])
{
    runtest("data/sighash.json");
    return 0;
}
