#ifndef __LIBCCOIN_MESSAGE_H__
#define __LIBCCOIN_MESSAGE_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <ccoin/core.h>
#include <ccoin/buffer.h>

#ifdef __cplusplus
extern "C" {
#endif

struct p2p_blockfile_hdr {
	unsigned char	netmagic[4];
	uint32_t	data_len;
};

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

enum {
	MSG_TX = 1,
	MSG_BLOCK,
};

extern void parse_message_hdr(struct p2p_message_hdr *hdr, const unsigned char *data);
extern bool message_valid(const struct p2p_message *msg);
extern cstring *message_str(const unsigned char netmagic[4],
		     const char *command_,
		     const void *data, uint32_t data_len);

struct msg_addr {
	parr	*addrs;		/* of bp_address */
};

static inline void msg_addr_init(struct msg_addr *ma)
{
	memset(ma, 0, sizeof(*ma));
}

extern bool deser_msg_addr(unsigned int protover, struct msg_addr *ma,
			   struct const_buffer *buf);
extern cstring *ser_msg_addr(unsigned int protover, const struct msg_addr *ma);
extern void msg_addr_free(struct msg_addr *ma);

/*
 * msg_getheaders is interchangeable with msg_getblocks
 */

struct msg_getblocks {
	struct bp_locator	locator;
	bu256_t			hash_stop;
};

static inline void msg_getblocks_init(struct msg_getblocks *gb)
{
	bp_locator_init(&gb->locator);
	bu256_zero(&gb->hash_stop);
}

extern bool deser_msg_getblocks(struct msg_getblocks *gb, struct const_buffer *buf);
extern cstring *ser_msg_getblocks(const struct msg_getblocks *gb);

static inline void msg_getblocks_free(struct msg_getblocks *gb)
{
	bp_locator_free(&gb->locator);
}

struct msg_headers {
	parr	*headers;
};

static inline void msg_headers_init(struct msg_headers *mh)
{
	memset(mh, 0, sizeof(*mh));
}

extern bool deser_msg_headers(struct msg_headers *mh, struct const_buffer *buf);
extern cstring *ser_msg_headers(const struct msg_headers *mh);
extern void msg_headers_free(struct msg_headers *mh);

/*
 * msg_pong is interchangeable with msg_ping
 */

struct msg_ping {
	uint64_t	nonce;
};

static inline void msg_ping_init(struct msg_ping *mp)
{
	memset(mp, 0, sizeof(*mp));
}

static inline void msg_ping_free(struct msg_ping *mp) {}
extern bool deser_msg_ping(unsigned int protover, struct msg_ping *ma,
			   struct const_buffer *buf);
extern cstring *ser_msg_ping(unsigned int protover, const struct msg_ping *ma);

struct msg_version {
	uint32_t	nVersion;
	uint64_t	nServices;
	int64_t		nTime;
	struct bp_address addrTo;
	struct bp_address addrFrom;
	uint64_t	nonce;
	char		strSubVer[80];
	uint32_t	nStartingHeight;
	bool		bRelay;
};

static inline void msg_version_init(struct msg_version *mv)
{
	memset(mv, 0, sizeof(*mv));
	mv->bRelay = true;
}

extern bool deser_msg_version(struct msg_version *mv, struct const_buffer *buf);
extern cstring *ser_msg_version(const struct msg_version *mv);
static inline void msg_version_free(struct msg_version *mv) {}

/*
 * msg_vinv used with "inv", "getdata"
 */

struct msg_vinv {
	parr	*invs;		/* of bp_inv */
};

static inline void msg_vinv_init(struct msg_vinv *mv)
{
	memset(mv, 0, sizeof(*mv));
}

extern bool deser_msg_vinv(struct msg_vinv *mv, struct const_buffer *buf);
extern cstring *ser_msg_vinv(const struct msg_vinv *mv);
extern void msg_vinv_free(struct msg_vinv *mv);
extern void msg_vinv_push(struct msg_vinv *mv, uint32_t msg_type,
		   const bu256_t *hash_in);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_MESSAGE_H__ */
