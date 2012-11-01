
#include "picocoin-config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ripemd.h>
#include <glib.h>
#include <jansson.h>
#include <ccoin/coredefs.h>
#include "picocoin.h"
#include "wallet.h"
#include <ccoin/message.h>
#include <ccoin/address.h>
#include <ccoin/serialize.h>
#include <ccoin/key.h>
#include <ccoin/util.h>
#include <ccoin/mbr.h>

static char *wallet_filename(void)
{
	char *filename = setting("wallet");
	if (!filename)
		filename = setting("w");
	return filename;
}

static bool deser_wallet_root(struct wallet *wlt, struct buffer *buf)
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

static bool load_rec_root(struct wallet *wlt, void *data, size_t data_len)
{
	struct buffer buf = { data, data_len };

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

static bool load_record(struct wallet *wlt, struct p2p_message *msg)
{
	if (!strncmp(msg->hdr.command, "privkey", sizeof(msg->hdr.command)))
		return load_rec_privkey(wlt, msg->data, msg->hdr.data_len);

	else if (!strncmp(msg->hdr.command, "root", sizeof(msg->hdr.command)))
		return load_rec_root(wlt, msg->data, msg->hdr.data_len);

	return true;	/* ignore unknown records */
}

struct wallet *load_wallet(void)
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

	wlt = calloc(1, sizeof(*wlt));

	wlt->keys = g_ptr_array_new_full(1000, g_free);

	struct buffer buf = { data->str, data->len };
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
	g_ptr_array_free(wlt->keys, TRUE);
	free(wlt);
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

bool store_wallet(struct wallet *wlt)
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

void wallet_free(struct wallet *wlt)
{
	unsigned int i;

	if (wlt->keys) {
		for (i = 0; i < wlt->keys->len; i++) {
			struct bp_key *key;

			key = g_ptr_array_index(wlt->keys, i);
			bp_key_free(key);
		}

		g_ptr_array_free(wlt->keys, TRUE);
		wlt->keys = NULL;
	}
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

	GString *btc_addr = bp_pubkey_get_address(key, 0);

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

	wlt = calloc(1, sizeof(*wlt));
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

	json_t *arr = json_array();

	if (!wlt->keys)
		goto out;

	unsigned int i;
	for (i = 0; i < wlt->keys->len; i++) {
		struct bp_key *key;
		GString *btc_addr;

		key = g_ptr_array_index(wlt->keys, i);

		btc_addr = bp_pubkey_get_address(key, 0);

		json_array_append_new(arr, json_string(btc_addr->str));

		g_string_free(btc_addr, TRUE);
	}

out:
	json_dumpf(arr, stdout, JSON_INDENT(2) | JSON_SORT_KEYS);
	putc('\n', stdout);
	json_decref(arr);
}

void wallet_info(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	json_t *obj = json_object();

	json_object_set_new(obj, "version", json_integer(wlt->version));
	json_object_set_new(obj, "n_privkeys",
		json_integer(wlt->keys ? wlt->keys->len : 0));

	char nmstr[32];
	sprintf(nmstr, "%02x%02x%02x%02x",
	       wlt->netmagic[0],
	       wlt->netmagic[1],
	       wlt->netmagic[2],
	       wlt->netmagic[3]);
	json_object_set_new(obj, "netmagic", json_string(nmstr));

	json_dumpf(obj, stdout, JSON_INDENT(2) | JSON_SORT_KEYS);
	putc('\n', stdout);
	json_decref(obj);
}

