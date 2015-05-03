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

struct wallet_key *wallet_key_new(void)
{
	struct wallet_key *wkey;

	wkey = calloc(1, sizeof(*wkey));
	if (!wkey)
		return NULL;

	if (!bp_key_init(&wkey->key))
		goto err_free;

	return wkey;

err_free:
	free(wkey);
	return NULL;
}

struct wallet_key *wallet_key_new_generate(void)
{
	struct wallet_key *wkey;

	wkey = wallet_key_new();
	if (!wkey)
		goto err_free;

	if (!bp_key_generate(&wkey->key))
		goto err_free;

	wkey->birthday = time(NULL);

	return wkey;

err_free:
	free(wkey);
	return NULL;
}

void wallet_key_free(struct wallet_key *wkey)
{
	if (!wkey)
		return;

	free(wkey);
}

cstring *ser_wallet_key(const struct wallet_key *wkey)
{
	void *privkey;
	size_t pk_len;
	cstring *rs;

	if (!bp_privkey_get(&wkey->key, &privkey, &pk_len))
		goto err_out;

	rs = cstr_new_sz(sizeof(uint64_t) + pk_len);
	if (!rs)
		goto err_free;

	ser_u64(rs, wkey->birthday);
	cstr_append_buf(rs, privkey, pk_len);

	free(privkey);
	return rs;

err_free:
	free(privkey);
err_out:
	return NULL;
}

bool deser_wallet_key(struct wallet_key *wkey, struct const_buffer *buf)
{
	if (!deser_u64(&wkey->birthday, buf))
		return false;

	if (!bp_privkey_set(&wkey->key, buf->p, buf->len))
		return false;

	buf->p += buf->len;
	buf->len = 0;
	return true;
}

struct wallet *wallet_new(const struct chain_info *chain)
{
	struct wallet *wlt;

	wlt = calloc(1, sizeof(*wlt));
	wlt->keys = parr_new(1000, free);
	wlt->chain = chain;

	return wlt;
}

void wallet_free(struct wallet *wlt)
{
	struct bp_key *key;

	if (!wlt)
		return;

	wallet_for_each_key(wlt, key)
		bp_key_free(key);

	parr_free(wlt->keys, true);
	wlt->keys = NULL;

	memset(wlt, 0, sizeof(*wlt));
	free(wlt);
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
