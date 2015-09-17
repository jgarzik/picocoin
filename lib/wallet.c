/* Copyright 2012 exMULTI, Inc.
 * Copyright 2015 Josh Cartwright <joshc@eso.teric.us>
 *
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <ccoin/address.h>
#include <ccoin/coredefs.h>
#include <ccoin/key.h>
#include <ccoin/mbr.h>
#include <ccoin/message.h>
#include <ccoin/wallet.h>
#include <ccoin/serialize.h>

bool wallet_init(struct wallet *wlt, const struct chain_info *chain)
{
	wlt->version = 1;
	wlt->chain = chain;
	wlt->keys = parr_new(1000, free);

	return wlt->keys != NULL;
}

void wallet_free(struct wallet *wlt)
{
	struct bp_key *key;

	if (!wlt)
		return;

	wallet_for_each_key(wlt, key)
		bp_key_free(key);

	parr_free(wlt->keys, true);
	memset(wlt, 0, sizeof(*wlt));
}

cstring *wallet_new_address(struct wallet *wlt)
{
	struct bp_key *key;

	key = calloc(1, sizeof(*key));
	if (!bp_key_init(key)) {
		free(key);
		fprintf(stderr, "wallet: key init failed\n");
		return NULL;
	}

	if (!bp_key_generate(key)) {
		bp_key_free(key);
		free(key);
		fprintf(stderr, "wallet: key gen failed\n");
		return NULL;
	}

	parr_add(wlt->keys, key);

	return bp_pubkey_get_address(key, wlt->chain->addr_pubkey);
}

static cstring *ser_wallet_root(const struct wallet *wlt)
{
	cstring *rs = cstr_new_sz(8);

	ser_u32(rs, wlt->version);
	ser_bytes(rs, &wlt->chain->netmagic[0], 4);

	return rs;
}

cstring *ser_wallet(const struct wallet *wlt)
{
	struct bp_key *key;

	cstring *rs = cstr_new_sz(20 * 1024);

	/*
	 * ser "root" record
	 */
	cstring *s_root = ser_wallet_root(wlt);
	cstring *recdata = message_str(wlt->chain->netmagic,
				       "root", s_root->str, s_root->len);
	cstr_append_buf(rs, recdata->str, recdata->len);
	cstr_free(recdata, true);
	cstr_free(s_root, true);

	/* ser "privkey" records */
	wallet_for_each_key(wlt, key) {
		void *privkey = NULL;
		size_t pk_len = 0;

		bp_privkey_get(key, &privkey, &pk_len);

		cstring *recdata = message_str(wlt->chain->netmagic,
					       "privkey",
					       privkey, pk_len);
		free(privkey);

		cstr_append_buf(rs, recdata->str, recdata->len);
		cstr_free(recdata, true);
	}

	return rs;
}

static bool deser_wallet_root(struct wallet *wlt, struct const_buffer *buf)
{
	unsigned char netmagic[4];

	if (!deser_u32(&wlt->version, buf))
		return false;

	if (!deser_bytes(&netmagic[0], buf, 4))
		return false;

	wlt->chain = chain_find_by_netmagic(netmagic);
	if (!wlt->chain)
		return false;

	return true;
}

static bool load_rec_privkey(struct wallet *wlt, const void *privkey, size_t pk_len)
{
	struct bp_key *key;

	key = calloc(1, sizeof(*key));
	if (!bp_key_init(key))
		goto err_out;
	if (!bp_privkey_set(key, privkey, pk_len))
		goto err_out_kf;

	parr_add(wlt->keys, key);

	return true;

err_out_kf:
	bp_key_free(key);
err_out:
	free(key);
	return false;
}

static bool load_rec_root(struct wallet *wlt, const void *data, size_t data_len)
{
	struct const_buffer buf = { data, data_len };

	if (!deser_wallet_root(wlt, &buf)) return false;

	if (wlt->version != 1) {
		fprintf(stderr, "wallet root: unsupported wallet version %u\n",
			wlt->version);
		return false;
	}

	return true;
}

static bool load_record(struct wallet *wlt, const struct p2p_message *msg)
{
	if (!strncmp(msg->hdr.command, "privkey", sizeof(msg->hdr.command)))
		return load_rec_privkey(wlt, msg->data, msg->hdr.data_len);

	else if (!strncmp(msg->hdr.command, "root", sizeof(msg->hdr.command)))
		return load_rec_root(wlt, msg->data, msg->hdr.data_len);

	return true;	/* ignore unknown records */
}

bool deser_wallet(struct wallet *wlt, struct const_buffer *buf)
{
	struct mbuf_reader mbr;

	mbr_init(&mbr, buf);

	while (mbr_read(&mbr)) {
		if (!load_record(wlt, &mbr.msg)) {
			mbr_free(&mbr);
			goto err_out;
		}
	}

	if (mbr.error) {
		mbr_free(&mbr);
		goto err_out;
	}

	return true;

err_out:
	fprintf(stderr, "wallet: invalid data found\n");
	return false;
}
