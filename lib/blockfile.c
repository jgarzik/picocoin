/* Copyright 2013 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ccoin/mbr.h>
#include <ccoin/message.h>
#include <ccoin/endian.h>


bool fread_block(int fd, struct p2p_message *msg, bool *read_ok)
{
	*read_ok = false;

	if (msg->data) {
		free(msg->data);
		msg->data = NULL;
	}

	struct p2p_blockfile_hdr hdr;

	/* read netmagic/size header */
	ssize_t rrc = read(fd, &hdr, sizeof(hdr));
	if (rrc != sizeof(hdr)) {
		if (rrc == 0)
			*read_ok = true;
		return false;
	}

	/* translate to P2P message header */
	memcpy(&msg->hdr.netmagic, &hdr.netmagic, sizeof(hdr.netmagic));
	strcpy(msg->hdr.command, "block");
	msg->hdr.data_len = le32toh(hdr.data_len);
	memset(&msg->hdr.hash, 0, sizeof(msg->hdr.hash));

	unsigned int data_len = msg->hdr.data_len;
	if (data_len > (100 * 1024 * 1024))
		return false;

	/* read block data */
	msg->data = malloc(data_len);

	rrc = read(fd, msg->data, data_len);
	if (rrc != data_len)
		goto err_out_data;

	*read_ok = true;
	return true;

err_out_data:
	free(msg->data);
	msg->data = NULL;

	return false;
}

