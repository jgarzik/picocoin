
#include "picocoin-config.h"

#include <ccoin/script.h>
#include <ccoin/script_eval.h>

bool bp_tx_sighash(bu256_t *hash, GString *scriptCode,
		   const struct bp_tx *txTo, unsigned int nIn,
		   int nHashType)
{
	if (!hash || !scriptCode || !txTo || !txTo->vin)
		return false;
	if (nIn >= txTo->vin->len)
		return false;
	
	bool rc = false;
	struct bp_tx txTmp;
	bp_tx_init(&txTmp);
	bp_tx_copy(&txTmp, txTo);

	/* TODO: find-and-delete OP_CODESEPARATOR from scriptCode */

	/* Blank out other inputs' signatures */
	unsigned int i;
	struct bp_txin *txin;
	for (i = 0; i < txTmp.vin->len; i++) {
		txin = g_ptr_array_index(txTmp.vin, i);
		g_string_set_size(txin->scriptSig, 0);

		if (i == nIn)
			g_string_append_len(txin->scriptSig,
					    scriptCode->str, scriptCode->len);
	}

	/* Blank out some of the outputs */
	if ((nHashType & 0x1f) == SIGHASH_NONE) {
		/* Wildcard payee */
		bp_tx_free_vout(&txTmp);
		txTmp.vout = g_ptr_array_new_full(1, g_free);

		/* Let the others update at will */
		for (i = 0; i < txTmp.vin->len; i++) {
			txin = g_ptr_array_index(txTmp.vin, i);
			if (i != nIn)
				txin->nSequence = 0;
		}
	}

	else if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
		/* Only lock-in the txout payee at same index as txin */
		unsigned int nOut = nIn;
		if (nOut >= txTmp.vout->len)
			goto out;

		g_ptr_array_set_size(txTmp.vout, nOut + 1);

		for (i = 0; i < nOut; i++) {
			struct bp_txout *txout;

			txout = g_ptr_array_index(txTmp.vout, i);
			bp_txout_set_null(txout);
		}

		/* Let the others update at will */
		for (i = 0; i < txTmp.vin->len; i++) {
			txin = g_ptr_array_index(txTmp.vin, i);
			if (i != nIn)
				txin->nSequence = 0;
		}
	}

	/* Blank out other inputs completely;
	   not recommended for open transactions */
	if (nHashType & SIGHASH_ANYONECANPAY) {
		if (nIn > 0)
			g_ptr_array_remove_range(txTmp.vin, 0, nIn);
		g_ptr_array_set_size(txTmp.vin, 1);
	}

	/* Serialize and hash */
	bp_tx_calc_sha256(&txTmp);
	bu256_copy(hash, &txTmp.sha256);

	rc = true;

out:
	bp_tx_free(&txTmp);
	return rc;
}

