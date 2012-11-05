/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ripemd.h>
#include <glib.h>
#include <ccoin/coredefs.h>
#include "picocoin.h"
#include "wallet.h"
#include <ccoin/message.h>
#include <ccoin/address.h>
#include <ccoin/serialize.h>
#include <ccoin/key.h>
#include <ccoin/util.h>
#include <ccoin/mbr.h>
#include <ccoin/hexcode.h>

static struct wallet *wallet_new(void)
{
	struct wallet *wlt;

	wlt = calloc(1, sizeof(*wlt));
	wlt->keys = g_ptr_array_new_full(1000, g_free);

	return wlt;
}

static void wallet_free(struct wallet *wlt)
{
	if (!wlt)
		return;

	if (wlt->keys) {
		unsigned int i;
		for (i = 0; i < wlt->keys->len; i++) {
			struct bp_key *key;

			key = g_ptr_array_index(wlt->keys, i);
			bp_key_free(key);
		}

		g_ptr_array_free(wlt->keys, TRUE);
		wlt->keys = NULL;
	}

	memset(wlt, 0, sizeof(*wlt));
	free(wlt);
}

static char *wallet_filename(void)
{
	char *filename = setting("wallet");
	if (!filename)
		filename = setting("w");
	return filename;
}

static bool deser_wallet_root(struct wallet *wlt, struct const_buffer *buf)
{
	if (!deser_u32(&wlt->version, buf)) return false;
	if (!deser_bytes(&wlt->netmagic[0], buf, 4)) return false;

	return true;
}

static GString *ser_wallet_root(const struct wallet *wlt)
{
	GString *rs = g_string_sized_new(8);

	ser_u32(rs, wlt->version);
	ser_bytes(rs, &wlt->netmagic[0], 4);

	return rs;
}

static bool load_rec_privkey(struct wallet *wlt, const void *privkey, size_t pk_len)
{
	struct bp_key *key;

	key = calloc(1, sizeof(*key));
	if (!bp_key_init(key))
		goto err_out;
	if (!bp_privkey_set(key, privkey, pk_len))
		goto err_out_kf;

	g_ptr_array_add(wlt->keys, key);

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

	if (memcmp(chain->netmagic, wlt->netmagic, 4)) {
		fprintf(stderr, "wallet root: foreign chain detected, aborting load.  Try 'chain-set' first.\n");
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

static struct wallet *load_wallet(void)
{
	char *passphrase = getenv("PICOCOIN_PASSPHRASE");
	if (!passphrase) {
		fprintf(stderr, "missing PICOCOIN_PASSPHRASE\n");
		return NULL;
	}

	char *filename = wallet_filename();
	if (!filename) {
		fprintf(stderr, "wallet: no filename\n");
		return NULL;
	}

	GString *data = read_aes_file(filename, passphrase, strlen(passphrase),
				      100 * 1024 * 1024);
	if (!data) {
		fprintf(stderr, "wallet: missing or invalid\n");
		return NULL;
	}

	struct wallet *wlt;

	wlt = wallet_new();

	struct const_buffer buf = { data->str, data->len };
	struct mbuf_reader mbr;

	mbr_init(&mbr, &buf);

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

	return wlt;

err_out:
	fprintf(stderr, "wallet: invalid data found\n");
	wallet_free(wlt);
	g_string_free(data, TRUE);
	return NULL;
}

static GString *ser_wallet(struct wallet *wlt)
{
	unsigned int i;

	GString *rs = g_string_sized_new(20 * 1024);

	/*
	 * ser "root" record
	 */
	GString *s_root = ser_wallet_root(wlt);
	GString *recdata = message_str(wlt->netmagic,
				       "root", s_root->str, s_root->len);
	g_string_append_len(rs, recdata->str, recdata->len);
	g_string_free(recdata, TRUE);
	g_string_free(s_root, TRUE);

	/* ser "privkey" records */
	if (wlt->keys) {
		for (i = 0; i < wlt->keys->len; i++) {
			struct bp_key *key;

			key = g_ptr_array_index(wlt->keys, i);

			void *privkey = NULL;
			size_t pk_len = 0;

			bp_privkey_get(key, &privkey, &pk_len);

			GString *recdata = message_str(wlt->netmagic,
						       "privkey",
						       privkey, pk_len);
			free(privkey);

			g_string_append_len(rs, recdata->str, recdata->len);
			g_string_free(recdata, TRUE);
		}
	}

	return rs;
}

static bool store_wallet(struct wallet *wlt)
{
	char *passphrase = getenv("PICOCOIN_PASSPHRASE");
	if (!passphrase) {
		fprintf(stderr, "wallet: Missing PICOCOIN_PASSPHRASE for AES crypto\n");
		return false;
	}

	char *filename = wallet_filename();
	if (!filename)
		return false;

	GString *plaintext = ser_wallet(wlt);
	if (!plaintext)
		return false;

	bool rc = write_aes_file(filename, passphrase, strlen(passphrase),
				 plaintext->str, plaintext->len);

	memset(plaintext->str, 0, plaintext->len);
	g_string_free(plaintext, TRUE);

	return rc;
}

static bool cur_wallet_load(void)
{
	if (!cur_wallet)
		cur_wallet = load_wallet();
	if (!cur_wallet) {
		fprintf(stderr, "wallet: no wallet loaded\n");
		return false;
	}

	return true;
}

void wallet_new_address(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	struct bp_key *key;

	key = calloc(1, sizeof(*key));
	if (!bp_key_init(key)) {
		free(key);
		fprintf(stderr, "wallet: key init failed\n");
		return;
	}

	if (!bp_key_generate(key)) {
		fprintf(stderr, "wallet: key gen failed\n");
		return;
	}

	g_ptr_array_add(wlt->keys, key);

	store_wallet(wlt);

	GString *btc_addr = bp_pubkey_get_address(key, chain->addr_pubkey);

	printf("%s\n", btc_addr->str);

	g_string_free(btc_addr, TRUE);
}

void cur_wallet_free(void)
{
	if (!cur_wallet)
		return;

	wallet_free(cur_wallet);
	free(cur_wallet);

	cur_wallet = NULL;
}

static void cur_wallet_update(struct wallet *wlt)
{
	if (!cur_wallet) {
		cur_wallet = wlt;
		return;
	}
	if (cur_wallet == wlt)
		return;

	cur_wallet_free();
	cur_wallet = wlt;
}

void wallet_create(void)
{
	char *filename = wallet_filename();
	if (!filename) {
		fprintf(stderr, "wallet: no filename\n");
		return;
	}

	if (access(filename, F_OK) == 0) {
		fprintf(stderr, "wallet: already exists, aborting\n");
		return;
	}

	struct wallet *wlt;

	wlt = wallet_new();
	wlt->version = 1;
	memcpy(wlt->netmagic, chain->netmagic, sizeof(wlt->netmagic));

	cur_wallet_update(wlt);

	if (!store_wallet(wlt)) {
		fprintf(stderr, "wallet: failed to store %s\n", filename);
		return;
	}
}

void wallet_addresses(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	printf("[\n");

	if (!wlt->keys)
		goto out;

	unsigned int i;
	for (i = 0; i < wlt->keys->len; i++) {
		struct bp_key *key;
		GString *btc_addr;

		key = g_ptr_array_index(wlt->keys, i);

		btc_addr = bp_pubkey_get_address(key, chain->addr_pubkey);

		printf("  \"%s\"%s\n",
		       btc_addr->str,
		       i == (wlt->keys->len - 1) ? "" : ",");

		g_string_free(btc_addr, TRUE);
	}

out:
	printf("]\n");
}

void wallet_info(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	printf("{\n");

	printf("  \"version\": %u,\n", wlt->version);
	printf("  \"n_privkeys\": %u,\n", wlt->keys ? wlt->keys->len : 0U);
	printf("  \"netmagic\": %02x%02x%02x%02x\n",
	       wlt->netmagic[0],
	       wlt->netmagic[1],
	       wlt->netmagic[2],
	       wlt->netmagic[3]);

	printf("}\n");
}

static void wallet_dump_keys(struct wallet *wlt)
{
	if (!wlt->keys)
		return;

	unsigned int i;
	for (i = 0; i < wlt->keys->len; i++) {
		struct bp_key *key;
		GString *btc_addr;

		key = g_ptr_array_index(wlt->keys, i);

		void *privkey = NULL, *pubkey = NULL;
		char *privkey_str = NULL, *pubkey_str = NULL;
		size_t priv_len = 0, pub_len = 0;

		if (!bp_privkey_get(key, &privkey, &priv_len)) {
			free(privkey);
			privkey = NULL;
			priv_len = 0;
		}

		if (!bp_pubkey_get(key, &pubkey, &pub_len)) {
			free(privkey);
			continue;
		}

		privkey_str = calloc(1, (priv_len * 2) + 1);
		if (priv_len)
			encode_hex(privkey_str, privkey, priv_len);
		pubkey_str = calloc(1, (pub_len * 2) + 1);
		encode_hex(pubkey_str, pubkey, pub_len);

		btc_addr = bp_pubkey_get_address(key, chain->addr_pubkey);

		printf("  [ \"%s\", \"%s\", \"%s\" ]%s\n",
		       btc_addr->str,
		       pubkey_str,
		       privkey_str,
		       (i == (wlt->keys->len - 1)) ? "" : ",");

		free(privkey);
		free(privkey_str);
		free(pubkey);
		free(pubkey_str);
		g_string_free(btc_addr, TRUE);
	}
}

void wallet_dump(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	printf("{\n");

	printf("  \"version\": %u,\n", wlt->version);
	printf("  \"netmagic\": %02x%02x%02x%02x,\n",
	       wlt->netmagic[0],
	       wlt->netmagic[1],
	       wlt->netmagic[2],
	       wlt->netmagic[3]);

	printf("  \"keys\": [\n");

	wallet_dump_keys(wlt);

	printf("  ]\n");

	printf("}\n");
}

