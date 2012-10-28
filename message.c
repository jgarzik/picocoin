
#include "picocoin-config.h"

#include <stdint.h>
#include <string.h>
#include <glib.h>
#include <openssl/sha.h>
#include "message.h"
#include "serialize.h"
#include "util.h"

void parse_message_hdr(struct p2p_message_hdr *hdr, const unsigned char *data)
{
	memcpy(hdr, data, P2P_HDR_SZ);
	hdr->data_len = GUINT32_FROM_LE(hdr->data_len);
}

bool message_valid(struct p2p_message *msg)
{
	if (!msg || !msg->data)
		return false;
	
	/* TODO: validate network magic */

	/* data checksum */
	unsigned char md32[4];

	bu_Hash4(md32, msg->data, msg->hdr.data_len);

	return memcmp(msg->hdr.hash, md32, sizeof(md32)) == 0;
}

GString *message_str(const unsigned char netmagic[4],
		     const char *command_,
		     const void *data, uint32_t data_len)
{
	GString *s = g_string_sized_new(P2P_HDR_SZ + data_len);

	/* network identifier (magic number) */
	g_string_append_len(s, (gchar *) netmagic, 4);

	/* command string */
	char command[12] = {};
	strncpy(command, command_, 12);
	g_string_append_len(s, command, 12);

	/* data length */
	uint32_t data_len_le = GUINT32_TO_LE(data_len);
	g_string_append_len(s, (gchar *) &data_len_le, 4);

	/* data checksum */
	unsigned char md32[4];

	bu_Hash4(md32, data, data_len);

	g_string_append_len(s, (gchar *) &md32[0], 4);

	/* data payload */
	if (data_len > 0)
		g_string_append_len(s, data, data_len);

	return s;
}

bool deser_msg_version(struct msg_version *mv, struct buffer *buf)
{
	memset(mv, 0, sizeof(*mv));

	if (!deser_u32(&mv->nVersion, buf)) return false;
	if (mv->nVersion == 10300)
		mv->nVersion = 300;
	if (!deser_u64(&mv->nServices, buf)) return false;
	if (!deser_s64(&mv->nTime, buf)) return false;
	if (!deser_bp_addr(mv->nVersion, &mv->addrTo, buf)) return false;

	if (mv->nVersion >= 106) {
		if (!deser_bp_addr(mv->nVersion, &mv->addrFrom, buf)) return false;
		if (!deser_u64(&mv->nonce, buf)) return false;
		if (!deser_str(mv->strSubVer, buf, sizeof(mv->strSubVer)))
			return false;
		if (mv->nVersion >= 209)
			if (!deser_u32(&mv->nStartingHeight, buf)) return false;
	}

	return true;
}

GString *ser_msg_version(const struct msg_version *mv)
{
	GString *s = g_string_sized_new(256);

	ser_u32(s, mv->nVersion);
	ser_u64(s, mv->nServices);
	ser_s64(s, mv->nTime);

	ser_bp_addr(s, mv->nVersion, &mv->addrTo);
	ser_bp_addr(s, mv->nVersion, &mv->addrFrom);

	ser_u64(s, mv->nonce);
	ser_str(s, mv->strSubVer, sizeof(mv->strSubVer));
	ser_u32(s, mv->nStartingHeight);

	return s;
}

bool deser_msg_addr(unsigned int protover, struct msg_addr *ma,
		    struct buffer *buf)
{
	memset(ma, 0, sizeof(*ma));

	ma->addrs = g_ptr_array_new_full(512, g_free);

	uint32_t vlen;
	if (!deser_varlen(&vlen, buf)) goto err_out;

	unsigned int i;
	for (i = 0; i < vlen; i++) {
		struct bp_address *addr;

		addr = calloc(1, sizeof(*addr));
		if (!deser_bp_addr(protover, addr, buf)) {
			free(addr);
			goto err_out;
		}

		g_ptr_array_add(ma->addrs, addr);
	}

	return true;

err_out:
	msg_addr_free(ma);
	return false;
}

GString *ser_msg_addr(unsigned int protover, const struct msg_addr *ma)
{
	GString *s = g_string_new(NULL);

	if (!ma) {
		ser_varlen(s, 0);
		return s;
	}

	ser_varlen(s, ma->addrs->len);

	unsigned int i;
	for (i = 0; i < ma->addrs->len; i++) {
		struct bp_address *addr;

		addr = g_ptr_array_index(ma->addrs, i);

		ser_bp_addr(s, protover, addr);
	}

	return s;
}

void msg_addr_free(struct msg_addr *ma)
{
	if (ma->addrs) {
		g_ptr_array_free(ma->addrs, TRUE);
		ma->addrs = NULL;
	}
}

