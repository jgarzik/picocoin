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
#include <ccoin/hdkeys.h>
#include <ccoin/serialize.h>
#include <ccoin/util.h>

#include <assert.h>
#include <stdio.h>

struct hd_extended_key_serialized {
	uint8_t data[78 + 1];	// 78 + NUL (the latter not written)
};

static void wallet_free_key(void *p)
{
	struct bp_key *key = p;

	if (!key)
		return;

	bp_key_free(key);
	memset(key, 0, sizeof(*key));
	free(key);
}

static void wallet_free_hdkey(void *p)
{
	struct hd_extended_key *hdkey = p;

	if (!hdkey)
		return;

	hd_extended_key_free(hdkey);
	memset(hdkey, 0, sizeof(*hdkey));
	free(hdkey);
}

static void wallet_free_account(void *p)
{
	struct wallet_account *acct = p;

	if (!acct)
		return;

	cstr_free(acct->name, true);

	memset(acct, 0, sizeof(*acct));
	free(acct);
}

bool wallet_init(struct wallet *wlt, const struct chain_info *chain)
{
	wlt->version = 1;
	wlt->chain = chain;
	wlt->def_acct = NULL;
	wlt->keys = parr_new(1000, wallet_free_key);
	wlt->hdmaster = parr_new(10, wallet_free_hdkey);
	wlt->accounts = parr_new(10, wallet_free_account);

	return ((wlt->keys != NULL) && (wlt->hdmaster != NULL));
}

void wallet_free(struct wallet *wlt)
{
	if (!wlt)
		return;

	cstr_free(wlt->def_acct, true);
	parr_free(wlt->keys, true);
	parr_free(wlt->hdmaster, true);
	parr_free(wlt->accounts, true);
	memset(wlt, 0, sizeof(*wlt));
}

static struct wallet_account *account_byname(struct wallet *wlt, const char *name)
{
	if (!wlt || !wlt->accounts || !wlt->accounts->len)
		return NULL;

	unsigned int i;
	for (i = 0; i < wlt->accounts->len; i++) {
		struct wallet_account *acct = parr_idx(wlt->accounts, i);
		if (!strcmp(name, acct->name->str))
			return acct;
	}

	return NULL;
}

cstring *wallet_new_address(struct wallet *wlt)
{
	struct hd_path_seg hdpath[] = {
		{ 44, true },	// BIP 44
		{ 0, true },	// chain: BTC
		{ 0, true },	// acct#
		{ 0, false },	// change?
		{ 0, false },	// key index
	};

	struct wallet_account *acct = account_byname(wlt, wlt->def_acct->str);
	if (!acct)
		return NULL;

	// patch HD path based on account settings
	hdpath[2].index = acct->acct_idx;
	hdpath[4].index = acct->next_key_idx;

	assert(wlt->hdmaster && (wlt->hdmaster->len > 0));
	struct hd_extended_key *master = parr_idx(wlt->hdmaster, 0);
	assert(master != NULL);

	struct hd_extended_key child;
	hd_extended_key_init(&child);

	if (!hd_derive(&child, master, hdpath, ARRAY_SIZE(hdpath))) {
		hd_extended_key_free(&child);
		return NULL;
	}

	acct->next_key_idx++;

	cstring *rs = bp_pubkey_get_address(&child.key,wlt->chain->addr_pubkey);

	hd_extended_key_free(&child);

	return rs;
}

static cstring *ser_wallet_root(const struct wallet *wlt)
{
	cstring *rs = cstr_new_sz(8);

	ser_u32(rs, wlt->version);
	ser_bytes(rs, &wlt->chain->netmagic[0], 4);

	const uint32_t n_settings = 1;
	ser_varlen(rs, n_settings);

	ser_str(rs, "def_acct", 64);
	ser_varstr(rs, wlt->def_acct);

	return rs;
}

static bool write_ek_ser_prv(struct hd_extended_key_serialized *out,
			     const struct hd_extended_key *ek)
{
	cstring s = { (char *)(out->data), 0, sizeof(out->data) };
	return hd_extended_key_ser_priv(ek, &s);
}

static void account_free(struct wallet_account *acct)
{
	if (!acct)
		return;

	cstr_free(acct->name, true);

	memset(acct, 0, sizeof(*acct));
	free(acct);
}

static bool deser_wallet_account(struct wallet *wlt, struct const_buffer *buf)
{
	struct wallet_account *acct;

	acct = calloc(1, sizeof(*acct));
	if (!acct)
		return false;

	if (!deser_varstr(&acct->name, buf) ||
	    !deser_u32(&acct->acct_idx, buf) ||
	    !deser_u32(&acct->next_key_idx, buf))
		goto err_out;

	parr_add(wlt->accounts, acct);

	return true;

err_out:
	account_free(acct);
	return false;
}

static void ser_account(cstring *s, const struct wallet_account *acct)
{
	ser_varstr(s, acct->name);
	ser_u32(s, acct->acct_idx);
	ser_u32(s, acct->next_key_idx);
}

cstring *ser_wallet(const struct wallet *wlt)
{
	struct bp_key *key;

	cstring *rs = cstr_new_sz(20 * 1024);

	/*
	 * ser "root" record
	 */
	{
	cstring *s_root = ser_wallet_root(wlt);
	cstring *recdata = message_str(wlt->chain->netmagic,
				       "root", s_root->str, s_root->len);
	cstr_append_buf(rs, recdata->str, recdata->len);
	cstr_free(recdata, true);
	cstr_free(s_root, true);
	}

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

	/* ser "hdmaster" records */
	struct hd_extended_key *hdkey;
	wallet_for_each_mkey(wlt, hdkey) {

		struct hd_extended_key_serialized hdraw;
		bool rc = write_ek_ser_prv(&hdraw, hdkey);
		assert(rc == true);

		cstring *recdata = message_str(wlt->chain->netmagic,
					       "hdmaster",
					       hdraw.data,
					       sizeof(hdraw.data) - 1);

		assert(recdata != NULL);

		cstr_append_buf(rs, recdata->str, recdata->len);
		cstr_free(recdata, true);
	}

	/* Ser "account" records */
	unsigned int i;
	for (i = 0; i < wlt->accounts->len; i++) {
		struct wallet_account *acct = parr_idx(wlt->accounts, i);

		cstring *acct_raw = cstr_new_sz(64);
		ser_account(acct_raw, acct);

		cstring *recdata = message_str(wlt->chain->netmagic,
					       "account",
					       acct_raw->str,
					       acct_raw->len);
		assert(recdata != NULL);

		cstr_append_buf(rs, recdata->str, recdata->len);
		cstr_free(recdata, true);
		cstr_free(acct_raw, true);
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

	uint32_t n_settings = 0;
	if (!deser_varlen(&n_settings, buf))
		return false;

	unsigned int i;
	for (i = 0; i < n_settings; i++) {
		cstring *key = NULL;
		cstring *value = NULL;

		if (!deser_varstr(&key, buf) ||
		    !deser_varstr(&value, buf))
			return false;

		if (!strcmp(key->str, "def_acct")) {
			wlt->def_acct = value;
			value = NULL;	// steal ref
		}

		cstr_free(key, true);
		cstr_free(value, true);
	}

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

static bool load_rec_hdmaster(struct wallet *wlt, const void *mkey, size_t mlen)
{
	struct hd_extended_key *hdkey;

	hdkey = calloc(1, sizeof(*hdkey));
	if (!hd_extended_key_init(hdkey)) {
		fprintf(stderr, "hdmaster fail 1\n");
		goto err_out;
	}
	if (!hd_extended_key_deser(hdkey, mkey, mlen)) {
		fprintf(stderr, "hdmaster fail 2\n");
		goto err_out_kf;
	}

	parr_add(wlt->hdmaster, hdkey);

	return true;

err_out_kf:
	hd_extended_key_free(hdkey);
err_out:
	free(hdkey);
	return false;
}

static bool load_rec_account(struct wallet *wlt, const void *data, size_t data_len)
{
	struct const_buffer buf = { data, data_len };

	if (!deser_wallet_account(wlt, &buf)) return false;

	return true;
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
	if (!strncmp(msg->hdr.command, "hdmaster", sizeof(msg->hdr.command)))
		return load_rec_hdmaster(wlt, msg->data, msg->hdr.data_len);

	else if (!strncmp(msg->hdr.command, "account", sizeof(msg->hdr.command)))
		return load_rec_account(wlt, msg->data, msg->hdr.data_len);

	else if (!strncmp(msg->hdr.command, "privkey", sizeof(msg->hdr.command)))
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
	return false;
}

bool wallet_create(struct wallet *wlt, const void *seed, size_t seed_len)
{
	struct hd_extended_key *hdkey;
	hdkey = calloc(1, sizeof(*hdkey));
	if (!hd_extended_key_init(hdkey) ||
	    !hd_extended_key_generate_master(hdkey, seed, sizeof(seed)))
		goto err_out_hdkey;

	struct wallet_account *acct;
	acct = calloc(1, sizeof(*acct));
	if (!acct)
		goto err_out_hdkey;

	acct->name = cstr_new("master");
	if (!acct->name)
		goto err_out_acct;

	wlt->def_acct = cstr_new("master");
	parr_add(wlt->hdmaster, hdkey);
	parr_add(wlt->accounts, acct);

	return true;

err_out_acct:
	account_free(acct);
err_out_hdkey:
	hd_extended_key_free(hdkey);
	free(hdkey);
	return false;
}

