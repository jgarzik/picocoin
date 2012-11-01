
#include "picocoin-config.h"

#include <string.h>
#include <unistd.h>
#include <ccoin/mbr.h>
#include <ccoin/message.h>

void mbr_init(struct mbuf_reader *mbr, struct const_buffer *buf)
{
	memset(mbr, 0, sizeof(*mbr));

	mbr->buf = buf;
}

bool mbr_read(struct mbuf_reader *mbr)
{
	struct const_buffer *buf = mbr->buf;

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

	mbr->msg.data = (void *) buf->p;
	buf->p += data_len;
	buf->len -= data_len;

	if (!message_valid(&mbr->msg)) {
		mbr->error = true;
		return false;
	}

	return true;
}

bool fread_message(int fd, struct p2p_message *msg, bool *read_ok)
{
	*read_ok = false;

	if (msg->data) {
		free(msg->data);
		msg->data = NULL;
	}

	unsigned char hdrbuf[P2P_HDR_SZ];

	ssize_t rrc = read(fd, hdrbuf, sizeof(hdrbuf));
	if (rrc != sizeof(hdrbuf)) {
		if (rrc == 0)
			*read_ok = true;
		return false;
	}

	parse_message_hdr(&msg->hdr, hdrbuf);

	unsigned int data_len = msg->hdr.data_len;
	if (data_len > (100 * 1024 * 1024))
		return false;
	
	msg->data = malloc(data_len);

	rrc = read(fd, msg->data, data_len);
	if (rrc != data_len)
		goto err_out_data;

	if (!message_valid(msg))
		goto err_out_data;

	*read_ok = true;
	return true;

err_out_data:
	free(msg->data);
	msg->data = NULL;

	return false;
}

