/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include "wallet.h"
#include "picocoin.h"                   // for cur_wallet, chain, setting

#include <ccoin/address.h>              // for bp_pubkey_get_address
#include <ccoin/base58.h>               // for base58_encode
#include <ccoin/buffer.h>               // for const_buffer
#include <ccoin/coredefs.h>             // for chain_info
#include <ccoin/crypto/aes_util.h>      // for read_aes_file, etc
#include <ccoin/cstr.h>                 // for cstring, cstr_free, etc
#include <ccoin/hdkeys.h>               // for hd_extended_key_ser_priv
#include <ccoin/hexcode.h>              // for encode_hex
#include <ccoin/key.h>                  // for bp_privkey_get, etc
#include <ccoin/parr.h>                 // for parr, parr_idx
#include <ccoin/wallet.h>               // for wallet, wallet_free, etc
#include <ccoin/compat.h>               // for parr_new

#include <jansson.h>                    // for json_object_set_new, etc
#include <openssl/rand.h>               // for RAND_bytes

#include <assert.h>                     // for assert
#include <stdbool.h>                    // for true, bool, false
#include <stddef.h>                     // for size_t
#include <stdint.h>                     // for uint8_t
#include <stdio.h>                      // for fprintf, printf, stderr, etc
#include <stdlib.h>                     // for free, calloc, getenv
#include <string.h>                     // for strlen, memset
#include <unistd.h>                     // for access, F_OK


struct hd_extended_key_serialized {
	uint8_t data[78 + 1];	// 78 + NUL (the latter not written)
};

static bool write_ek_ser_prv(struct hd_extended_key_serialized *out,
			     const struct hd_extended_key *ek)
{
	cstring s = { (char *)(out->data), 0, sizeof(out->data) };
	return hd_extended_key_ser_priv(ek, &s);
}

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

	if (!deser_wallet(wlt, &buf)) {
		fprintf(stderr, "wallet: deserialization failed\n");
		goto err_out;
	}

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

	char seed[256];
	RAND_bytes((unsigned char *) &seed[0], sizeof(seed));

	char seed_str[(sizeof(seed) * 2) + 1];
	encode_hex(seed_str, seed, sizeof(seed));
	printf("Record this HD seed (it will only be shown once):\n"
	       "%s\n", seed_str);

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

	if (!wallet_create(wlt, seed, sizeof(seed))) {
		fprintf(stderr, "wallet: failed to create new wallet\n");
		free(wlt);
		return;
	}

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
	printf("  \"n_hd_extkeys\": %zu,\n", wlt->hdmaster ? wlt->hdmaster->len : 0);
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

		json_t *o = json_object();

		void *privkey = NULL;
		size_t priv_len = 0;
		if (bp_privkey_get(key, &privkey, &priv_len)) {
			cstring *privkey_str = str2hex(privkey, priv_len);
			json_object_set_new(o, "privkey", json_string(privkey_str->str));
			cstr_free(privkey_str, true);
			free(privkey);
			privkey = NULL;
		}

		void *pubkey = NULL;
		size_t pub_len = 0;
		if (!bp_pubkey_get(key, &pubkey, &pub_len)) {
			json_decref(o);
			continue;
		}

		if (pubkey) {
			cstring *pubkey_str = str2hex(pubkey, pub_len);
			json_object_set_new(o, "pubkey", json_string(pubkey_str->str));
			cstr_free(pubkey_str, true);

			cstring *btc_addr = bp_pubkey_get_address(key, chain->addr_pubkey);
			json_object_set_new(o, "address", json_string(btc_addr->str));

			cstr_free(btc_addr, true);

			free(pubkey);
		}

		json_array_append_new(keys_a, o);
	}
}

static void wallet_dump_hdkeys(json_t *hdkeys_a, struct wallet *wlt)
{
	struct hd_extended_key *hdkey;

	wallet_for_each_mkey(wlt, hdkey) {
		json_t *o = json_object();

		struct hd_extended_key_serialized hdraw;
		bool rc = write_ek_ser_prv(&hdraw, hdkey);
		assert(rc == true);

		cstring *hdstr = base58_encode(hdraw.data, sizeof(hdraw.data)-1);
		assert(hdstr != NULL);

		json_object_set_new(o, "hdpriv", json_string(hdstr->str));

		cstr_free(hdstr, true);

		json_array_append_new(hdkeys_a, o);
	}
}

static void wallet_dump_accounts(json_t *accounts, struct wallet *wlt)
{
	struct wallet_account *acct;
	unsigned int i;

	for (i = 0; i < wlt->accounts->len; i++) {
		acct = parr_idx(wlt->accounts, i);

		json_t *o = json_object();

		json_object_set_new(o, "name", json_string(acct->name->str));
		json_object_set_new(o, "acct_idx", json_integer(acct->acct_idx));
		json_object_set_new(o, "next_key_idx", json_integer(acct->next_key_idx));

		json_array_append_new(accounts, o);
	}
}

void cur_wallet_dump(void)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;
	json_t *o = json_object();

	json_object_set_new(o, "version", json_integer(wlt->version));
	json_object_set_new(o, "def_acct", json_string(wlt->def_acct->str));

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

	json_t *hdkeys_a = json_array();

	wallet_dump_hdkeys(hdkeys_a, wlt);

	json_object_set_new(o, "hdmaster", hdkeys_a);

	json_t *accounts = json_array();

	wallet_dump_accounts(accounts, wlt);

	json_object_set_new(o, "accounts", accounts);

	json_dumpf(o, stdout, JSON_INDENT(2) | JSON_SORT_KEYS);
	json_decref(o);

	printf("\n");
}

void cur_wallet_createAccount(const char *acct_name)
{
	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	if (!wallet_createAccount(wlt, acct_name)) {
		fprintf(stderr, "wallet: creation of account %s failed\n", acct_name);
		return;
	}

	if (!store_wallet(wlt)) {
		fprintf(stderr, "wallet: failed to store\n");
		return;
	}
}

void cur_wallet_defaultAccount(const char *acct_name)
{
	if (!wallet_valid_name(acct_name)) {
		fprintf(stderr, "Invalid account name %s\n", acct_name);
		return;
	}

	if (!cur_wallet_load())
		return;
	struct wallet *wlt = cur_wallet;

	struct wallet_account *acct = account_byname(wlt, acct_name);
	if (!acct) {
		fprintf(stderr, "wallet: unknown account %s\n", acct_name);
		return;
	}

	cstr_free(wlt->def_acct, true);
	wlt->def_acct = cstr_new(acct_name);

	if (!store_wallet(wlt)) {
		fprintf(stderr, "wallet: failed to store\n");
		return;
	}
}

