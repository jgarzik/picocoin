/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <jansson.h>
#include <ccoin/cstr.h>
#include <ccoin/parr.h>
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
	size_t slen = strlen(TEST_SRCDIR) + 1 + strlen(basename) + 1;
	char *ret = malloc(slen);
	if (ret)
		snprintf(ret, slen, "%s/%s", TEST_SRCDIR, basename);
	return ret;
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

static char **strsplit_set(const char *s, const char *delim)
{
	// init delimiter lookup table
	const char *stmp;
	bool is_delim[256];
	memset(&is_delim, 0, sizeof(is_delim));

	stmp = delim;
	while (*stmp) {
		is_delim[(unsigned char)*stmp] = true;
		stmp++;
	}

	bool in_str = true;
	parr *pa = parr_new(0, free);
	cstring *cs = cstr_new(NULL);
	if (!pa || !cs)
		goto err_out;

	while (*s) {
		unsigned char ch = (unsigned char) *s;
		if (is_delim[ch]) {
			if (in_str) {
				in_str = false;
				parr_add(pa, cs->str);

				cstr_free(cs, false);
				cs = cstr_new(NULL);
				if (!cs)
					goto err_out;
			}
		} else {
			in_str = true;
			if (!cstr_append_c(cs, ch))
				goto err_out;
		}
		s++;
	}

	parr_add(pa, cs->str);
	cstr_free(cs, false);

	parr_add(pa, NULL);

	char **ret = (char **) pa->data;
	parr_free(pa, false);

	return ret;

err_out:
	parr_free(pa, true);
	cstr_free(cs, true);
	return NULL;
}

static void freev(void *vec_)
{
	void **vec = vec_;
	if (!vec)
		return;

	unsigned int idx = 0;
	while (vec[idx]) {
		free(vec[idx]);
		vec[idx] = NULL;
		idx++;
	}

	free(vec);
}

cstring *parse_script_str(const char *enc)
{
	char **tokens = strsplit_set(enc, " \t\n");
	assert (tokens != NULL);

	cstring *script = cstr_new_sz(64);

	unsigned int idx;
	for (idx = 0; tokens[idx] != NULL; idx++) {
		char *token = tokens[idx];

		if (is_digitstr(token)) {
			int64_t v = strtoll(token, NULL, 10);
			bsp_push_int64(script, v);
		}

		else if (is_hexstr(token, true)) {
			cstring *raw = hex2str(token);
			cstr_append_buf(script, raw->str, raw->len);
			cstr_free(raw, true);
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

	freev(tokens);

	return script;
}

