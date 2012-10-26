
#include "picocoin-config.h"

#include "coredefs.h"
#include "picocoin.h"
#include "wallet.h"
#include "message.h"
#include "serialize.h"
#include "key.h"

static bool load_rec_privkey(struct wallet *wlt, void *privkey, size_t pk_len)
{
	if (pk_len != 32)		/* 256 bit privkey required */
		return false;

	struct bp_key key;

	bp_key_init(&key);
	bp_privkey_set(&key, privkey, pk_len);

	g_array_append_val(wlt->keys, key);

	return true;
}

static bool load_record(struct wallet *wlt, struct p2p_message *msg)
{
	if (!strncmp(msg->hdr.command, "privkey", sizeof(msg->hdr.command)))
		return load_rec_privkey(wlt, msg->data, msg->hdr.data_len);

	return true;	/* ignore unknown records */
}

struct wallet *load_wallet(void)
{
	char *passphrase = getenv("PICOCOIN_PASSPHRASE");
	if (!passphrase)
		return NULL;
	
	char *filename = setting("wallet");
	if (!filename)
		filename = setting("w");
	if (!filename)
		return NULL;
	
	GString *data = read_aes_file(filename, passphrase, strlen(passphrase),
				      100 * 1024 * 1024);
	if (!data)
		return NULL;

	struct wallet *wlt;

	wlt = calloc(1, sizeof(*wlt));

	struct buffer buf = { data->str, data->len };
	struct p2p_message msg;
	unsigned char hdrbuf[P2P_HDR_SZ];

	while (deser_bytes(hdrbuf, &buf, P2P_HDR_SZ)) {
		parse_message_hdr(&msg.hdr, hdrbuf);
		msg.data = buf.p;
		if (buf.len < msg.hdr.data_len)
			goto err_out;

		buf.p += msg.hdr.data_len;
		buf.len -= msg.hdr.data_len;

		if (!message_valid(&msg))
			goto err_out;

		if (!load_record(wlt, &msg))
			goto err_out;
	}

	return wlt;

err_out:
	free(wlt);
	g_string_free(data, TRUE);
	return NULL;
}

static GString *ser_wallet(struct wallet *wlt)
{
	unsigned int i;

	GString *rs = g_string_new(NULL);

	if (wlt->keys) {
		for (i = 0; i < wlt->keys->len; i++) {
			struct bp_key *key;

			key = &g_array_index(wlt->keys, struct bp_key, i);

			void *privkey = NULL;
			size_t pk_len = 0;

			bp_privkey_get(key, &privkey, &pk_len);

			GString *recdata = message_str(netmagic_main,
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
	if (!passphrase)
		return false;
	
	char *filename = setting("wallet");
	if (!filename)
		filename = setting("w");
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

			key = &g_array_index(wlt->keys, struct bp_key, i);
			bp_key_free(key);
		}

		g_array_free(wlt->keys, TRUE);
		wlt->keys = NULL;
	}
}

void wallet_new_address(void)
{
	if (!cur_wallet)
		cur_wallet = load_wallet();
	if (!cur_wallet)
		return;
	
	struct wallet *wlt = cur_wallet;

	struct bp_key key;

	bp_key_init(&key);
	bp_key_generate(&key);

	g_array_append_val(wlt->keys, key);

	store_wallet(wlt);
}

