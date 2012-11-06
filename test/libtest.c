/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <jansson.h>
#include <glib.h>
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

