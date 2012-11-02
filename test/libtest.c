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
	return json_load_file(filename, JSON_REJECT_DUPLICATES, &err);
}

char *test_filename(const char *basename)
{
	return g_strdup_printf("%s/%s", TEST_SRCDIR, basename);
}
