
#include "picocoin-config.h"

#include <string.h>
#include <assert.h>
#include <glib.h>
#include <ccoin/util.h>
#include <ccoin/script.h>
#include <ccoin/core.h>
#include "libtest.h"

static void test_txout(const struct bp_txout *txout)
{
	struct buffer buf = { txout->scriptPubKey->str,
			      txout->scriptPubKey->len };

	struct bscript_parser bsp;
	struct bscript_op op;
	GList *ops = NULL;

	/*
	 * parse script
	 */

	bsp_init(&bsp);
	bsp_start(&bsp, &buf);

	while (bsp_getop(&op, &bsp)) {
		struct bscript_op *op_p;

		op_p = g_memdup(&op, sizeof(op));
		ops = g_list_append(ops, op_p);
	}

	assert(!bsp.error);

	bsp_free(&bsp);

	/*
	 * build script
	 */

	GList *tmp = ops;
	GString *s = g_string_sized_new(256);
	while (tmp) {
		struct bscript_op *op_p;

		op_p = tmp->data;
		tmp = tmp->next;

		if (is_bsp_pushdata(op_p->op)) {
			bsp_push_data(s, op_p->data.p, op_p->data.len);
		} else {
			bsp_push_op(s, op_p->op);
		}
	}

	g_list_free_full(ops, g_free);

	/* byte-compare original and newly created scripts */
	assert(g_string_equal(s, txout->scriptPubKey));

	g_string_free(s, TRUE);
}

static void runtest(const char *ser_fn_base)
{
	char *ser_fn = test_filename(ser_fn_base);

	void *data = NULL;
	size_t data_len = 0;

	bool rc = bu_read_file(ser_fn, &data, &data_len, 100 * 1024 * 1024);
	assert(rc);

	struct bp_tx tx;
	bp_tx_init(&tx);

	struct buffer buf = { data, data_len };

	rc = deser_bp_tx(&tx, &buf);
	assert(rc);

	unsigned int n_out;
	for (n_out = 0; n_out < tx.vout->len; n_out++) {
		struct bp_txout *txout;

		txout = g_ptr_array_index(tx.vout, n_out);
		test_txout(txout);
	}

	bp_tx_free(&tx);
	free(data);
	free(ser_fn);
}

int main (int argc, char *argv[])
{
	const char *opn = GetOpName(OP_PUBKEY);
	assert(!strcmp(opn, "OP_PUBKEY"));

	opn = GetOpName(OP_INVALIDOPCODE);
	assert(!strcmp(opn, "<unknown>"));

	runtest("tx3e0dc3da.ser");

	return 0;
}

