/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/base58.h>               // for base58_decode_check, etc
#include <ccoin/coredefs.h>             // for bitc_address_type, etc
#include <ccoin/cstr.h>                 // for cstring, cstr_free, etc
#include <ccoin/hexcode.h>              // for hex2str, decode_hex
#include <ccoin/key.h>                  // for bitc_key_static_shutdown
#include <ccoin/crypto/ripemd160.h>     // for RIPEMD160_DIGEST_LENGTH
#include "libtest.h"                    // for dumphex, read_json, etc

#include <jansson.h>

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for bool, true
#include <stddef.h>                     // for size_t
#include <stdio.h>                      // for fprintf, NULL, stderr
#include <stdlib.h>                     // for free, calloc
#include <string.h>                     // for strcmp, memcmp, strlen

static void test_encode(const char *hexstr, const char *enc)
{
	size_t hs_len = strlen(hexstr) / 2;
	unsigned char *raw = calloc(1, hs_len);
	size_t out_len;

	bool rc = decode_hex(raw, hs_len, hexstr, &out_len);
	if (!rc) {
		fprintf(stderr, "raw %p, sizeof(raw) %lu, hexstr %p %s\n",
			raw, hs_len, hexstr, hexstr);
		assert(rc);
	}

	cstring *s = base58_encode(raw, out_len);
	if (strcmp(s->str, enc)) {
		fprintf(stderr, "base58 mismatch: '%s' vs expected '%s'\n",
			s->str, enc);
		assert(!strcmp(s->str, enc));
	}

	free(raw);
	cstr_free(s, true);
}

static void test_decode(const char *hexstr, const char *base58_str)
{
	size_t hs_len = strlen(hexstr) / 2;
	unsigned char *raw = calloc(1, hs_len);
	size_t out_len;

	bool rc = decode_hex(raw, hs_len, hexstr, &out_len);
	if (!rc) {
		fprintf(stderr, "raw %p, sizeof(raw) %lu, hexstr %p %s\n",
			raw, hs_len, hexstr, hexstr);
		assert(rc);
	}

	cstring *s = base58_decode(base58_str);
	if (memcmp(s->str, raw, out_len < s->len ? out_len : s->len)) {
		dumphex("decode have", s->str, s->len);
		dumphex("decode want", raw, out_len);
		assert(memcmp(s->str, raw, out_len) == 0);
	}
	if (s->len != out_len) {
		fprintf(stderr, "decode len: have %u, want %u\n",
			(unsigned int) s->len,
			(unsigned int) out_len);
		dumphex("decode have", s->str, s->len);
		dumphex("decode want", raw, out_len);
		assert(s->len == out_len);
	}

	free(raw);
	cstr_free(s, true);
}

static void runtest_encdec(const char *json_base_fn)
{
	char *json_fn = test_filename(json_base_fn);
	json_t *tests = read_json(json_fn);
	assert(json_is_array(tests));

	size_t n_tests = json_array_size(tests);
	unsigned int idx;

	for (idx = 0; idx < n_tests; idx++) {
		json_t *test = json_array_get(tests, idx);
	    assert(json_is_array(test));
	    assert(json_array_size(test) == 2);

		json_t *j_raw = json_array_get(test, 0);
		json_t *j_enc = json_array_get(test, 1);
		assert(json_is_string(j_raw));
		assert(json_is_string(j_enc));

		test_encode(json_string_value(j_raw),
			    json_string_value(j_enc));
		test_decode(json_string_value(j_raw),
			    json_string_value(j_enc));
	}

	free(json_fn);
	json_decref(tests);
}

static void test_privkey_valid_enc(const char *base58_str,
				cstring *payload,
				bool compress, bool is_testnet)
{
	assert(payload != NULL);

	cstring *pl = cstr_new_sz(payload->len + 1);
	cstr_append_buf(pl, payload->str, payload->len);
	if (compress)
		cstr_append_c(pl, 1);

	cstring *b58 = base58_encode_check(
		is_testnet ? PRIVKEY_ADDRESS_TEST : PRIVKEY_ADDRESS, true,
		pl->str, pl->len);
	assert(b58 != NULL);
	if (strcmp(b58->str, base58_str)) {
		fprintf(stderr, "base58: have %s, expected %s\n",
			b58->str, base58_str);
		assert(!strcmp(b58->str, base58_str));
	}

	cstr_free(b58, true);
	cstr_free(pl, true);
	cstr_free(payload, true);
}

static void test_pubkey_valid_enc(const char *base58_str,
				cstring *payload,
				const char *addrtype_str,
				bool is_testnet)
{
	assert(payload != NULL);

	bool addrtype_pubkey = (strcmp(addrtype_str, "pubkey") == 0);
	bool addrtype_script = (strcmp(addrtype_str, "script") == 0);
	assert(addrtype_pubkey || addrtype_script);

	enum bp_address_type addrtype;
	if (addrtype_pubkey) {
		if (is_testnet)
			addrtype = PUBKEY_ADDRESS_TEST;
		else
			addrtype = PUBKEY_ADDRESS;
	} else {
		if (is_testnet)
			addrtype = SCRIPT_ADDRESS_TEST;
		else
			addrtype = SCRIPT_ADDRESS;
	}

	cstring *b58 = base58_encode_check(
		addrtype, true,
		payload->str, payload->len);
	if (strcmp(b58->str, base58_str)) {
		fprintf(stderr, "base58: have %s, expected %s\n",
			b58->str, base58_str);
		assert(!strcmp(b58->str, base58_str));
	}

	cstr_free(b58, true);
	cstr_free(payload, true);
}

static void test_privkey_valid_dec(const char *base58_str,
				cstring *payload,
				bool compress, bool is_testnet)
{
	assert(payload != NULL);

	cstring *pl = cstr_new_sz(payload->len + 1);
	cstr_append_buf(pl, payload->str, payload->len);
	if (compress)
		cstr_append_c(pl, 1);

	unsigned char addrtype;
	cstring *dec = base58_decode_check(&addrtype, base58_str);
	assert(dec != NULL);

	if (is_testnet)
		assert(addrtype == PRIVKEY_ADDRESS_TEST);
	else
		assert(addrtype == PRIVKEY_ADDRESS);

	if (compress) {
		assert(dec->len == 33);
		assert(dec->str[32] == 1);
	} else
		assert(dec->len == 32);

	assert(dec->len == pl->len);
	assert(memcmp(dec->str, pl->str, pl->len) == 0);

	cstr_free(dec, true);
	cstr_free(pl, true);
	cstr_free(payload, true);
}

static void test_pubkey_valid_dec(const char *base58_str,
				cstring *payload,
				const char *addrtype_str,
				bool is_testnet)
{
	assert(payload != NULL);

	bool addrtype_pubkey = (strcmp(addrtype_str, "pubkey") == 0);
	bool addrtype_script = (strcmp(addrtype_str, "script") == 0);
	assert(addrtype_pubkey || addrtype_script);

	enum bp_address_type addrtype;
	if (addrtype_pubkey) {
		if (is_testnet)
			addrtype = PUBKEY_ADDRESS_TEST;
		else
			addrtype = PUBKEY_ADDRESS;
	} else {
		if (is_testnet)
			addrtype = SCRIPT_ADDRESS_TEST;
		else
			addrtype = SCRIPT_ADDRESS;
	}

	unsigned char addrtype_dec;
	cstring *dec = base58_decode_check(&addrtype_dec, base58_str);
	assert(dec != NULL);

	assert(addrtype == addrtype_dec);
	assert(dec->len == RIPEMD160_DIGEST_LENGTH);
	assert(payload->len == dec->len);
	assert(memcmp(payload->str, dec->str, dec->len) == 0);

	cstr_free(dec, true);
	cstr_free(payload, true);
}

static void runtest_keys_valid(const char *json_base_fn)
{
	char *json_fn = test_filename(json_base_fn);
	json_t *tests = read_json(json_fn);
	assert(json_is_array(tests));

	size_t n_tests = json_array_size(tests);
	unsigned int idx;

	for (idx = 0; idx < n_tests; idx++) {
		json_t *test = json_array_get(tests, idx);
	    assert(json_is_array(test));
	    assert(json_array_size(test) == 3);

		json_t *j_base58 = json_array_get(test, 0);
		json_t *j_payload = json_array_get(test, 1);
		assert(json_is_string(j_base58));
		assert(json_is_string(j_payload));

		json_t *j_meta = json_array_get(test, 2);
		assert(json_is_object(j_meta));

		json_t *j_addrtype = json_object_get(j_meta, "addrType");
		assert(!j_addrtype || json_is_string(j_addrtype));

		json_t *j_compress = json_object_get(j_meta, "isCompressed");
		assert(!j_compress || json_is_true(j_compress) ||
		       json_is_false(j_compress));

		bool is_privkey = json_is_true(json_object_get(j_meta, "isPrivkey"));
		bool is_testnet = json_is_true(json_object_get(j_meta, "isTestnet"));

		if (is_privkey) {
			test_privkey_valid_enc(
				json_string_value(j_base58),
				hex2str(json_string_value(j_payload)),
				json_is_true(j_compress),
				is_testnet);
			test_privkey_valid_dec(
				json_string_value(j_base58),
				hex2str(json_string_value(j_payload)),
				json_is_true(j_compress),
				is_testnet);
		} else {
			test_pubkey_valid_enc(
				json_string_value(j_base58),
				hex2str(json_string_value(j_payload)),
				json_string_value(j_addrtype),
				is_testnet);
			test_pubkey_valid_dec(
				json_string_value(j_base58),
				hex2str(json_string_value(j_payload)),
				json_string_value(j_addrtype),
				is_testnet);
		}
	}

	free(json_fn);
	json_decref(tests);
}

static void runtest_keys_invalid(const char *json_base_fn)
{
	char *json_fn = test_filename(json_base_fn);
	json_t *tests = read_json(json_fn);
	assert(json_is_array(tests));

	size_t n_tests = json_array_size(tests);
	unsigned int idx;

	for (idx = 0; idx < n_tests; idx++) {

	    json_t *test = json_array_get(tests, idx);
	    assert(json_is_array(test));
	    assert(json_array_size(test) == 1);

	    json_t *j_base58 = json_array_get(test, 0);
	    assert(json_is_string(j_base58));

	    unsigned char addrtype;
	    cstring *payload = base58_decode_check(&addrtype, json_string_value(j_base58));
	    bool is_valid = (payload != NULL);

	    if (is_valid)
			if ((addrtype == PUBKEY_ADDRESS_TEST) ||
				(addrtype == PUBKEY_ADDRESS) ||
				(addrtype == SCRIPT_ADDRESS_TEST) ||
				(addrtype == SCRIPT_ADDRESS))
				    is_valid = (payload->len == RIPEMD160_DIGEST_LENGTH);
			else if
				((addrtype == PRIVKEY_ADDRESS_TEST) ||
				(addrtype == PRIVKEY_ADDRESS))
				    is_valid = (payload->len == 32 || payload->len == 33 && payload->str[32] == 1);
			else is_valid = false;

	    cstr_free(payload, true);
	    assert(!is_valid);
	}

	free(json_fn);
	json_decref(tests);
}

int main (int argc, char *argv[])
{
	runtest_encdec("base58_encode_decode.json");
	runtest_keys_valid("base58_keys_valid.json");
	runtest_keys_invalid("base58_keys_invalid.json");

	bp_key_static_shutdown();
	return 0;
}
