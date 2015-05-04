/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdlib.h>
#include <string.h>
#include <ccoin/util.h>
#include <ccoin/buffer.h>

unsigned long buffer_hash(const void *key_)
{
	const struct buffer *buf = key_;

	return djb2_hash(0x1721, buf->p, buf->len);
}

bool buffer_equal(const void *a_, const void *b_)
{
	const struct buffer *a = a_;
	const struct buffer *b = b_;

	if (a->len != b->len)
		return false;
	return memcmp(a->p, b->p, a->len) == 0;
}

void buffer_free(void *struct_buffer)
{
	struct buffer *buf = struct_buffer;
	if (!buf)
		return;

	free(buf->p);
	free(buf);
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

