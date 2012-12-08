/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <ccoin/util.h>
#include <ccoin/buffer.h>

guint g_buffer_hash(gconstpointer key_)
{
	const struct buffer *buf = key_;

	return djb2_hash(0x1721, buf->p, buf->len);
}

gboolean g_buffer_equal(gconstpointer a_, gconstpointer b_)
{
	const struct buffer *a = a_;
	const struct buffer *b = b_;

	if (a->len != b->len)
		return FALSE;
	return memcmp(a->p, b->p, a->len) == 0;
}

void buffer_free(struct buffer *buf)
{
	if (!buf)
		return;

	free(buf->p);
	free(buf);
}

void g_buffer_free(gpointer data)
{
	buffer_free(data);
}

struct buffer *buffer_copy(const void *data, size_t data_len)
{
	struct buffer *buf;
	buf = malloc(sizeof(*buf));
	if (!buf)
		goto err_out;

	buf->p = malloc(data_len);
	if (!buf->p)
		goto err_out_free;

	memcpy(buf->p, data, data_len);
	buf->len = data_len;

	return buf;

err_out_free:
	free(buf);
err_out:
	return NULL;
}

