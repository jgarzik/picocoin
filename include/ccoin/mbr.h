#ifndef __LIBCCOIN_MBR_H__
#define __LIBCCOIN_MBR_H__

#include <stdbool.h>
#include <ccoin/buffer.h>
#include <ccoin/message.h>

struct mbuf_reader {
	struct buffer		*buf;
	bool			error;
	bool			eof;

	struct p2p_message	msg;
};

extern void mbr_init(struct mbuf_reader *mbr, struct buffer *buf);
extern bool mbr_read(struct mbuf_reader *mbr);
static inline void mbr_free(struct mbuf_reader *mbr) {}
extern bool fread_message(int fd, struct p2p_message *msg, bool *read_ok);

#endif /* __LIBCCOIN_MBR_H__ */
