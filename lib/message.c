/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>
#include <ccoin/message.h>
#include <ccoin/serialize.h>
#include <ccoin/util.h>
#include <ccoin/compat.h>		/* for parr_new */
#include <ccoin/endian.h>

void parse_message_hdr(struct p2p_message_hdr *hdr, const unsigned char *data)
{
	memcpy(hdr, data, P2P_HDR_SZ);
	hdr->data_len = le32toh(hdr->data_len);
}

bool message_valid(const struct p2p_message *msg)
{
	if (!msg)
		return false;

	/* data checksum */
	unsigned char md32[4];

	if (msg->hdr.data_len)
		bu_Hash4(md32, msg->data, msg->hdr.data_len);
	else
		bu_Hash4(md32, "", 0);

	if (memcmp(msg->hdr.hash, md32, sizeof(md32)))
		return false;

	return true;
}

cstring *message_str(const unsigned char netmagic[4],
		     const char *command_,
		     const void *data, uint32_t data_len)
{
	cstring *s = cstr_new_sz(P2P_HDR_SZ + data_len);

	/* network identifier (magic number) */
	cstr_append_buf(s, netmagic, 4);

	/* command string */
	char command[12] = {};
	strncpy(command, command_, 12);
	cstr_append_buf(s, command, 12);

	/* data length */
	uint32_t data_len_le = htole32(data_len);
	cstr_append_buf(s, &data_len_le, 4);

	/* data checksum */
	unsigned char md32[4];

	bu_Hash4(md32, data, data_len);

	cstr_append_buf(s, &md32[0], 4);

	/* data payload */
	if (data_len > 0)
		cstr_append_buf(s, data, data_len);

	return s;
}

bool deser_msg_addr(unsigned int protover, struct msg_addr *ma,
		    struct const_buffer *buf)
{
	memset(ma, 0, sizeof(*ma));

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	ma->addrs = parr_new(vlen, free);

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bp_address *addr;

		addr = calloc(1, sizeof(*addr));
		if (!deser_bp_addr(protover, addr, buf)) {
			free(addr);
			goto err_out;
		}

		parr_add(ma->addrs, addr);
	}

	return true;

err_out:
	msg_addr_free(ma);
	return false;
}

cstring *ser_msg_addr(unsigned int protover, const struct msg_addr *ma)
{
	cstring *s = cstr_new(NULL);

	if (!ma || !ma->addrs || !ma->addrs->len) {
		ser_varlen(s, 0);
		return s;
	}

	ser_varlen(s, ma->addrs->len);

	unsigned int i;
	for (i = 0; i < ma->addrs->len; i++) {
		struct bp_address *addr;

		addr = parr_idx(ma->addrs, i);

		ser_bp_addr(s, protover, addr);
	}

	return s;
}

void msg_addr_free(struct msg_addr *ma)
{
	if (ma->addrs) {
		parr_free(ma->addrs, true);
		ma->addrs = NULL;
	}
}

bool deser_msg_getblocks(struct msg_getblocks *gb, struct const_buffer *buf)
{
	msg_getblocks_free(gb);

	if (!deser_bp_locator(&gb->locator, buf)) return false;
	if (!deser_u256(&gb->hash_stop, buf)) return false;
	return true;
}

cstring *ser_msg_getblocks(const struct msg_getblocks *gb)
{
	cstring *s = cstr_new_sz(256);

	ser_bp_locator(s, &gb->locator);
	ser_u256(s, &gb->hash_stop);

	return s;
}

bool deser_msg_headers(struct msg_headers *mh, struct const_buffer *buf)
{
	msg_headers_free(mh);

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	mh->headers = parr_new(vlen, free);

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bp_block *block;

		block = calloc(1, sizeof(*block));
		if (!deser_bp_block(block, buf)) {
			free(block);
			goto err_out;
		}

		parr_add(mh->headers, block);
	}

	return true;

err_out:
	msg_headers_free(mh);
	return false;
}

cstring *ser_msg_headers(const struct msg_headers *mh)
{
	cstring *s = cstr_new(NULL);

	if (!mh || !mh->headers || !mh->headers->len) {
		ser_varlen(s, 0);
		return s;
	}

	ser_varlen(s, mh->headers->len);

	unsigned int i;
	for (i = 0; i < mh->headers->len; i++) {
		struct bp_block *block;

		block = parr_idx(mh->headers, i);

		ser_bp_block(s, block);
	}

	return s;
}

void msg_headers_free(struct msg_headers *mh)
{
	if (!mh)
		return;

	if (mh->headers) {
		unsigned int i;

		for (i = 0; i < mh->headers->len; i++) {
			struct bp_block *block;

			block = parr_idx(mh->headers, i);
			bp_block_free(block);
		}

		parr_free(mh->headers, true);
		mh->headers = NULL;
	}
}

bool deser_msg_ping(unsigned int protover, struct msg_ping *mp,
		    struct const_buffer *buf)
{
	msg_ping_free(mp);
	msg_ping_init(mp);

	if (protover > BIP0031_VERSION)
		if (!deser_u64(&mp->nonce, buf)) return false;

	return true;
}

cstring *ser_msg_ping(unsigned int protover, const struct msg_ping *mp)
{
	cstring *s = cstr_new(NULL);

	if (mp && (protover > BIP0031_VERSION))
		ser_u64(s, mp->nonce);

	return s;
}

bool deser_msg_version(struct msg_version *mv, struct const_buffer *buf)
{
	memset(mv, 0, sizeof(*mv));

	if (!deser_u32(&mv->nVersion, buf)) return false;
	if (mv->nVersion == 10300)
		mv->nVersion = 300;
	if (!deser_u64(&mv->nServices, buf)) return false;
	if (!deser_s64(&mv->nTime, buf)) return false;
	if (!deser_bp_addr(MIN_PROTO_VERSION, &mv->addrTo, buf)) return false;

	if (mv->nVersion >= 106) {
		if (!deser_bp_addr(MIN_PROTO_VERSION, &mv->addrFrom, buf)) return false;
		if (!deser_u64(&mv->nonce, buf)) return false;
		if (!deser_str(mv->strSubVer, buf, sizeof(mv->strSubVer)))
			return false;
		if (mv->nVersion >= 209)
			if (!deser_u32(&mv->nStartingHeight, buf)) return false;
	}
	if (mv->nVersion >= 70001) {
		if (!deser_bool(&mv->bRelay, buf)) return false;
	} else {
		mv->bRelay = true;
	}

	return true;
}

cstring *ser_msg_version(const struct msg_version *mv)
{
	cstring *s = cstr_new_sz(256);

	ser_u32(s, mv->nVersion);
	ser_u64(s, mv->nServices);
	ser_s64(s, mv->nTime);

	ser_bp_addr(s, MIN_PROTO_VERSION, &mv->addrTo);
	ser_bp_addr(s, MIN_PROTO_VERSION, &mv->addrFrom);

	ser_u64(s, mv->nonce);
	ser_str(s, mv->strSubVer, sizeof(mv->strSubVer));
	ser_u32(s, mv->nStartingHeight);
	if (mv->nVersion >= 70001) {
		ser_bool(s, mv->bRelay);
	}

	return s;
}

bool deser_msg_vinv(struct msg_vinv *mv, struct const_buffer *buf)
{
	msg_vinv_free(mv);

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) return false;

	mv->invs = parr_new(vlen, free);

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bp_inv *inv;

		inv = calloc(1, sizeof(*inv));
		if (!deser_bp_inv(inv, buf)) {
			free(inv);
			goto err_out;
		}

		parr_add(mv->invs, inv);
	}

	return true;

err_out:
	msg_vinv_free(mv);
	return false;
}

cstring *ser_msg_vinv(const struct msg_vinv *mv)
{
	cstring *s = cstr_new(NULL);

	if (!mv || !mv->invs || !mv->invs->len) {
		ser_varlen(s, 0);
		return s;
	}

	ser_varlen(s, mv->invs->len);

	unsigned int i;
	for (i = 0; i < mv->invs->len; i++) {
		struct bp_inv *inv;

		inv = parr_idx(mv->invs, i);

		ser_bp_inv(s, inv);
	}

	return s;
}

void msg_vinv_free(struct msg_vinv *mv)
{
	if (!mv)
		return;

	if (mv->invs) {
		parr_free(mv->invs, true);
		mv->invs = NULL;
	}
}

void msg_vinv_push(struct msg_vinv *mv, uint32_t msg_type,
		   const bu256_t *hash_in)
{
	if (!mv->invs)
		mv->invs = parr_new(512, free);

	struct bp_inv *inv = malloc(sizeof(struct bp_inv));
	inv->type = msg_type;
	bu256_copy(&inv->hash, hash_in);

	parr_add(mv->invs, inv);
}

