#ifndef __LIBCCOIN_MBR_H__
#define __LIBCCOIN_MBR_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <ccoin/buffer.h>
#include <ccoin/message.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mbuf_reader {
	struct const_buffer	*buf;
	bool			error;
	bool			eof;

	struct p2p_message	msg;
};

extern void mbr_init(struct mbuf_reader *mbr, struct const_buffer *buf);
extern bool mbr_read(struct mbuf_reader *mbr);
static inline void mbr_free(struct mbuf_reader *mbr) {}
extern bool fread_message(int fd, struct p2p_message *msg, bool *read_ok);
extern bool fread_block(int fd, struct p2p_message *msg, bool *read_ok);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_MBR_H__ */
