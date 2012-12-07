/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <assert.h>
#include <jansson.h>
#include <glib.h>
#include <ccoin/script.h>
#include <ccoin/hexcode.h>
#include "libtest.h"

json_t *read_json(const char *filename)
{
	json_error_t err;
	json_t *ret;

	ret = json_load_file(filename, JSON_REJECT_DUPLICATES, &err);

	return ret;
}

char *test_filename(const char *basename)
{
	return g_strdup_printf("%s/%s", TEST_SRCDIR, basename);
}

void dumphex(const char *prefix, const void *p_, size_t len)
{
	if (prefix)
		fprintf(stderr, "%s: ", prefix);

	unsigned int i;
	const unsigned char *p = p_;
	for (i = 0; i < len; i++) {
		fprintf(stderr, "%02x", p[i]);
	}

	fprintf(stderr, "\n");
}

static bool is_digitstr(const char *s)
{
	if (*s == '-')
		s++;

	while (*s) {
		if (!isdigit(*s))
			return false;
		s++;
	}

	return true;
}

GString *parse_script_str(const char *enc)
{
	char **tokens = g_strsplit_set(enc, " \t\n", 0);
	assert (tokens != NULL);

	GString *script = g_string_sized_new(64);

	unsigned int idx;
	for (idx = 0; tokens[idx] != NULL; idx++) {
		char *token = tokens[idx];

		if (is_digitstr(token)) {
			int64_t v = strtoll(token, NULL, 10);
			bsp_push_int64(script, v);
		}

		else if (is_hexstr(token, true)) {
			GString *raw = hex2str(token);
			g_string_append_len(script, raw->str, raw->len);
			g_string_free(raw, TRUE);
		}

		else if ((strlen(token) >= 2) &&
			 (token[0] == '\'') &&
			 (token[strlen(token) - 1] == '\''))
			bsp_push_data(script, &token[1], strlen(token) - 2);

		else if (GetOpType(token) != OP_INVALIDOPCODE)
			bsp_push_op(script, GetOpType(token));

		else
			assert(!"parse error");
	}

	g_strfreev(tokens);

	return script;
}

