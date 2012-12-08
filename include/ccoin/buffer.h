#ifndef __LIBCCOIN_BUFFER_H__
#define __LIBCCOIN_BUFFER_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <glib.h>

struct buffer {
	void		*p;
	size_t		len;
};

struct const_buffer {
	const void	*p;
	size_t		len;
};

extern guint g_buffer_hash(gconstpointer key_);
extern gboolean g_buffer_equal(gconstpointer a_, gconstpointer b_);
extern void buffer_free(struct buffer *buf);
extern void g_buffer_free(gpointer data);
extern struct buffer *buffer_copy(const void *data, size_t data_len);

#endif /* __LIBCCOIN_BUFFER_H__ */
