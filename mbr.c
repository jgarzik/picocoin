
#include "picocoin-config.h"

#include <string.h>
#include "mbr.h"
#include "message.h"

void mbr_init(struct mbuf_reader *mbr, struct buffer *buf)
{
	memset(mbr, 0, sizeof(*mbr));

	mbr->buf = buf;
}

bool mbr_read(struct mbuf_reader *mbr)
{
	struct buffer *buf = mbr->buf;

	if (buf->len == 0) {
		mbr->eof = true;
		return false;
	}
	if (buf->len < P2P_HDR_SZ) {
		mbr->error = true;
		return false;
	}

	parse_message_hdr(&mbr->msg.hdr, buf->p);
	buf->p += P2P_HDR_SZ;
	buf->len -= P2P_HDR_SZ;

	unsigned int data_len = mbr->msg.hdr.data_len;
	if (buf->len < data_len) {
		mbr->error = true;
		return false;
	}

	mbr->msg.data = buf->p;
	buf->p += data_len;
	buf->len -= data_len;

	if (!message_valid(&mbr->msg)) {
		mbr->error = true;
		return false;
	}

	return true;
}

