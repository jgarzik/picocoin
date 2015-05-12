/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/ripemd.h>
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
#include <ccoin/hexcode.h>
#include <ccoin/compat.h>		/* for parr_new */
#include <ccoin/wallet.h>

static char *wallet_filename(void)
{
	char *filename = setting("wallet");
	if (!filename)
		filename = setting("w");
	return filename;
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

	cstring *data = read_aes_file(filename, passphrase, strlen(passphrase),
				      100 * 1024 * 1024);
	if (!data) {
		fprintf(stderr, "wallet: missing or invalid\n");
		return NULL;
	}

	struct wallet *wlt = calloc(1, sizeof(*wlt));
	if (!wlt) {
		fprintf(stderr, "wallet: failed to allocate wallet\n");
		cstr_free(data, true);
		return NULL;
	}

	if (!wallet_init(wlt, chain)) {
		free(wlt);
		cstr_free(data, true);
		return NULL;
	}

	struct const_buffer buf = { data->str, data->len };

	if (!deser_wallet(wlt, &buf))
		goto err_out;

	if (chain != wlt->chain) {
		fprintf(stderr, "wallet root: foreign chain detected, aborting load.  Try 'chain-set' first.\n");
		goto err_out;
	}

	return wlt;

err_out:
	fprintf(stderr, "wallet: invalid data found\n");
	wallet_free(wlt);
	cstr_free(data, true);
	return NULL;
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

	cstring *plaintext = ser_wallet(wlt);
	if (!plaintext)
		return false;

	bool rc = write_aes_file(filename, passphrase, strlen(passphrase),
				 plaintext->str, plaintext->len);

	memset(plaintext->str, 0, plaintext->len);
	cstr_free(plaintext, true);

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

void cur_wallet_new_address(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;
	cstring *btc_addr;

	btc_addr = wallet_new_address(wlt);

	store_wallet(wlt);

	printf("%s\n", btc_addr->str);

	cstr_free(btc_addr, true);
}

void cur_wallet_free(void)
{
	if (!cur_wallet)
		return;

	wallet_free(cur_wallet);
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

void cur_wallet_create(void)
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

	struct wallet *wlt = calloc(1, sizeof(*wlt));

	if (!wlt) {
		fprintf(stderr, "wallet: failed to allocate wallet\n");
		return;
	}

	if (!wallet_init(wlt, chain)) {
		fprintf(stderr, "wallet: failed to initialize wallet\n");
		free(wlt);
		return;
	}

	cur_wallet_update(wlt);

	if (!store_wallet(wlt)) {
		fprintf(stderr, "wallet: failed to store %s\n", filename);
		wallet_free(wlt);
		free(wlt);
		return;
	}
}

void cur_wallet_addresses(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;
	struct bp_key *key;
	unsigned int i;

	printf("[\n");

	wallet_for_each_key_numbered(wlt, key, i) {
		cstring *btc_addr;

		btc_addr = bp_pubkey_get_address(key, chain->addr_pubkey);

		printf("  \"%s\"%s\n",
		       btc_addr->str,
		       i == (wlt->keys->len - 1) ? "" : ",");

		cstr_free(btc_addr, true);
	}

	printf("]\n");
}

void cur_wallet_info(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	printf("{\n");

	printf("  \"version\": %u,\n", wlt->version);
	printf("  \"n_privkeys\": %zu,\n", wlt->keys ? wlt->keys->len : 0);
	printf("  \"netmagic\": %02x%02x%02x%02x\n",
	       wlt->chain->netmagic[0],
	       wlt->chain->netmagic[1],
	       wlt->chain->netmagic[2],
	       wlt->chain->netmagic[3]);

	printf("}\n");
}

static void wallet_dump_keys(json_t *keys_a, struct wallet *wlt)
{
	struct bp_key *key;

	wallet_for_each_key(wlt, key) {

		void *privkey = NULL, *pubkey = NULL;
		size_t priv_len = 0, pub_len = 0;
		json_t *o = json_object();

		if (!bp_privkey_get(key, &privkey, &priv_len)) {
			free(privkey);
			privkey = NULL;
			priv_len = 0;
		}

		if (priv_len) {
			char *privkey_str = calloc(1, (priv_len * 2) + 1);
			encode_hex(privkey_str, privkey, priv_len);
			json_object_set_new(o, "privkey", json_string(privkey_str));
			free(privkey_str);
			free(privkey);
		}

		if (!bp_pubkey_get(key, &pubkey, &pub_len)) {
			json_decref(o);
			continue;
		}

		if (pub_len) {
			char *pubkey_str = calloc(1, (pub_len * 2) + 1);
			encode_hex(pubkey_str, pubkey, pub_len);
			json_object_set_new(o, "pubkey", json_string(pubkey_str));
			free(pubkey_str);

			cstring *btc_addr = bp_pubkey_get_address(key, chain->addr_pubkey);
			json_object_set_new(o, "address", json_string(btc_addr->str));

			cstr_free(btc_addr, true);

			free(pubkey);
		}

		json_array_append_new(keys_a, o);
	}
}

void cur_wallet_dump(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;
	json_t *o = json_object();

	json_object_set_new(o, "version", json_integer(wlt->version));

	char nmstr[32];
	sprintf(nmstr, "%02x%02x%02x%02x",
	       wlt->chain->netmagic[0],
	       wlt->chain->netmagic[1],
	       wlt->chain->netmagic[2],
	       wlt->chain->netmagic[3]);

	json_object_set_new(o, "netmagic", json_string(nmstr));

	json_t *keys_a = json_array();

	wallet_dump_keys(keys_a, wlt);

	json_object_set_new(o, "keys", keys_a);

	json_dumpf(o, stdout, JSON_INDENT(2) | JSON_SORT_KEYS);
	json_decref(o);

	printf("\n");
}

