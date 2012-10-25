#ifndef __PICOCOIN_MESSAGE_H__
#define __PICOCOIN_MESSAGE_H__

#include <stdint.h>
#include <stdbool.h>
#include "core.h"

#define P2P_HDR_SZ	(4 + 12 + 4 + 4)

struct p2p_message_hdr {
	unsigned char	netmagic[4];
	char		command[12];
	uint32_t	data_len;
	unsigned char	hash[4];
};

struct p2p_message {
	struct p2p_message_hdr	hdr;
	void			*data;
};

struct msg_version {
	uint32_t	nVersion;
	uint64_t	nServices;
	int64_t		nTime;
	struct bp_address addrTo;
	struct bp_address addrFrom;
	uint64_t	nonce;
	char		strSubVer[80];
	uint32_t	nStartingHeight;
};

extern bool deser_version(struct msg_version *mv, struct buffer *buf);

#endif /* __PICOCOIN_MESSAGE_H__ */
