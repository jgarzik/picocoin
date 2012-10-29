
#include "picocoin-config.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <jansson.h>
#include "libtest.h"
#include <ccoin/base58.h>
#include <ccoin/hexcode.h>

static void test_encdec(const char *hexstr, const char *enc)
{
	unsigned char raw[strlen(hexstr)];
	size_t out_len;

	bool rc = decode_hex(raw, sizeof(raw), hexstr, &out_len);
	assert(rc);

	GString *s = base58_encode(raw, out_len);
	assert(s->len == strlen(enc));
	assert(!strcmp(s->str, enc));
}

int main (int argc, char *argv[])
{
	char *fn = NULL;

	fn = g_strdup_printf("%s/base58_encode_decode.json", TEST_SRCDIR);
	json_t *data = read_json(fn);
	assert(json_is_array(data));

	size_t n_tests = json_array_size(data);
	unsigned int i;

	for (i = 0; i < n_tests; i++) {
		json_t *inner;

		inner = json_array_get(data, i);
		assert(json_is_array(inner));

		json_t *j_raw = json_array_get(inner, 0);
		json_t *j_enc = json_array_get(inner, 1);
		assert(json_is_string(j_raw));
		assert(json_is_string(j_enc));

		test_encdec(json_string_value(j_raw),
			    json_string_value(j_enc));
	}

	return 0;
}

