
#include "picocoin-config.h"

#include <openssl/bn.h>
#include <glib.h>
#include "util.h"

static const char base58_chars[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

GString *base58_encode(const void *data_, size_t data_len)
{
	const unsigned char *data = data_;
	BIGNUM bn58, bn0, bn, dv, rem;
	BN_CTX *ctx;

	ctx = BN_CTX_new();
	BN_init(&bn58);
	BN_init(&bn0);
	BN_init(&bn);
	BN_init(&dv);
	BN_init(&rem);

	BN_set_word(&bn58, 58);
	BN_set_word(&bn0, 0);

	unsigned char swapbuf[data_len + 1];
	reverse_copy(swapbuf + sizeof(swapbuf) - 1, data, data_len);
	swapbuf[0] = 0;

	bn_setvch(&bn, swapbuf, sizeof(swapbuf));

	GString *rs = g_string_sized_new(data_len * 138 / 100 + 1);

	while (BN_cmp(&bn, &bn0) > 0) {
		if (!BN_div(&dv, &rem, &bn, &bn58, ctx))
			goto err_out;
		BN_copy(&bn, &dv);

		unsigned int c = BN_get_word(&rem);
		g_string_append_c(rs, base58_chars[c]);
	}

	unsigned int i;
	for (i = 0; i < data_len; i++) {
		if (data[i] == 0)
			g_string_append_c(rs, base58_chars[0]);
		else
			break;
	}

	GString *rs_swap = g_string_sized_new(rs->len);
	g_string_set_size(rs_swap, rs->len);
	reverse_copy((unsigned char *) rs_swap->str + rs->len - 1,
		     (unsigned char *) rs->str, rs->len);

	g_string_free(rs, TRUE);
	rs = rs_swap;

out:
	BN_clear_free(&bn58);
	BN_clear_free(&bn0);
	BN_clear_free(&bn);
	BN_clear_free(&dv);
	BN_clear_free(&rem);
	BN_CTX_free(ctx);

	return rs;

err_out:
	g_string_free(rs, TRUE);
	rs = NULL;
	goto out;
}

GString *base58_address_encode(unsigned char addrtype, const void *data,
			       size_t data_len)
{
	GString *s = g_string_sized_new(data_len + 1 + 4);

	g_string_append_c(s, addrtype);
	g_string_append_len(s, data, data_len);

	unsigned char md32[4];
	Hash4(md32, s->str, s->len);

	g_string_append_len(s, (gchar *) md32, 4);

	GString *s_enc = base58_encode(s->str, s->len);

	g_string_free(s, TRUE);

	return s_enc;
}

