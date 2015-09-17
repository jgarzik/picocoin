#include "picocoin-config.h"

#include <assert.h>
#include <stdio.h>
#include <ccoin/buffer.h>
#include <ccoin/coredefs.h>
#include <ccoin/cstr.h>
#include <ccoin/key.h>
#include <ccoin/wallet.h>

static bool key_eq(const struct bp_key *key1,
		   const struct bp_key *key2)
{
	void *data1, *data2;
	size_t len1, len2;
	int ret;

	if (!bp_privkey_get(key1, &data1, &len1))
		return false;

	if (!bp_privkey_get(key2, &data2, &len2)){
		free(data1);
		return false;
	}

	if (len1 != len2) {
		free(data2);
		free(data1);
		return false;
	}

	ret = memcmp(data1, data2, len1);

	free(data1);
	free(data2);

	return ret == 0;
}

static bool wallet_eq(const struct wallet *wlt1,
		      const struct wallet *wlt2)
{
	unsigned int i;

	if (wlt1->version != wlt2->version)
		return false;

	if (wlt1->chain != wlt2->chain)
		return false;

	if (wlt1->keys->len != wlt2->keys->len)
		return false;

	for (i = 0; i < wlt1->keys->len; i++) {
		const struct bp_key *key1, *key2;

		key1 = parr_idx(wlt1->keys, i);
		key2 = parr_idx(wlt2->keys, i);

		if (!key_eq(key1, key2))
			return false;
	}

	return true;
}

/*
 * Given a wallet, wlt, ensure the following condition holds:
 *
 *   deser(ser(wlt)) == wlt
 *
 * Note that this implies ensuring that the key order is preserved
 * during serialization/deserialization, which may be a more strict
 * than required.
 */
static void check_serialization(const struct wallet *wlt)
{
	struct wallet deser;
	cstring *ser = ser_wallet(wlt);
	struct const_buffer buf;

	assert(wallet_init(&deser, wlt->chain));
	assert(ser != NULL);

	buf.p = ser->str;
	buf.len = ser->len;

	assert(deser_wallet(&deser, &buf));
	assert(wallet_eq(wlt, &deser));

	cstr_free(ser, true);
	wallet_free(&deser);
}

static void check_with_chain(const struct chain_info *chain)
{
	struct wallet wlt;
	unsigned int i;

	assert(wallet_init(&wlt, chain));

	for (i = 0; i < 100; i++) {
		cstring *addr;

		addr = wallet_new_address(&wlt);
		assert(addr != NULL);

		cstr_free(addr, true);
	}

	check_serialization(&wlt);

	wallet_free(&wlt);

}

int main(int argc, char *argv[])
{
	unsigned int i;

	for (i = 0; i < CHAIN_LAST; i++)
		check_with_chain(&chain_metadata[i]);

	return 0;
}
