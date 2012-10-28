#ifndef __LIBCCOIN_MESSAGE_H__
#define __LIBCCOIN_MESSAGE_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <glib.h>
#include "core.h"
#include "buffer.h"

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

extern void parse_message_hdr(struct p2p_message_hdr *hdr, const unsigned char *data);
extern bool message_valid(struct p2p_message *msg);
extern GString *message_str(const unsigned char netmagic[4],
		     const char *command_,
		     const void *data, uint32_t data_len);

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

static inline void msg_version_init(struct msg_version *mv)
{
	memset(mv, 0, sizeof(*mv));
}

extern bool deser_msg_version(struct msg_version *mv, struct buffer *buf);
extern GString *ser_msg_version(const struct msg_version *mv);
static inline void msg_version_free(struct msg_version *mv) {}

struct msg_addr {
	GPtrArray	*addrs;
};

extern bool deser_msg_addr(unsigned int protover, struct msg_addr *ma, struct buffer *buf);
extern GString *ser_msg_addr(unsigned int protover, const struct msg_addr *ma);
extern void msg_addr_free(struct msg_addr *ma);

#endif /* __LIBCCOIN_MESSAGE_H__ */
