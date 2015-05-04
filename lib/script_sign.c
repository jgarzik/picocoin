
#include "picocoin-config.h"

#include <ccoin/script.h>
#include <ccoin/key.h>
#include <ccoin/core.h>
#include <ccoin/buint.h>
#include <ccoin/key.h>
#include <ccoin/util.h>

static bool sign1(const bu160_t *key_id, struct bp_keystore *ks,
		  const bu256_t *hash, int nHashType,
		  cstring *scriptSig)
{
	struct bp_key key;
	bool rc = false;

	bp_key_init(&key);

	/* find private key in keystore */
	if (!bkeys_key_get(ks, key_id, &key))
		goto out;

	void *sig = NULL;
	size_t siglen = 0;

	/* sign hash with private key */
	if (!bp_sign(&key, hash, sizeof(*hash), &sig, &siglen))
		goto out;

	/* append nHashType to signature */
	unsigned char ch = (unsigned char) nHashType;
	sig = realloc(sig, siglen + 1);
	memcpy(sig + siglen, &ch, 1);
	siglen++;

	/* append signature to scriptSig */
	bsp_push_data(scriptSig, sig, siglen);
	free(sig);

	rc = true;

out:
	bp_key_free(&key);
	return rc;
}

bool bp_script_sign(struct bp_keystore *ks, const cstring *fromPubKey,
		    const struct bp_tx *txTo, unsigned int nIn,
		    int nHashType)
{
	if (!txTo || !txTo->vin || nIn >= txTo->vin->len)
		return false;

	struct bp_txin *txin = parr_idx(txTo->vin, nIn);

	/* get signature hash */
	bu256_t hash;
	bp_tx_sighash(&hash, fromPubKey, txTo, nIn, nHashType);

	/* match fromPubKey against templates, to find what pubkey[hashes]
	 * are required for signing
	 */
	struct bscript_addr addrs;
	if (!bsp_addr_parse(&addrs, fromPubKey->str, fromPubKey->len))
		return false;

	cstring *scriptSig = cstr_new_sz(64);
	bool rc = false;
	bu160_t key_id;
	struct buffer *kbuf;

	/* sign, based on script template matched above */
	switch (addrs.txtype) {
	case TX_PUBKEY:
		kbuf = addrs.pub->data;
		bu_Hash160((unsigned char *)&key_id, kbuf->p, kbuf->len);

		if (!sign1(&key_id, ks, &hash, nHashType, scriptSig))
			goto out;
		break;

	case TX_PUBKEYHASH:
		kbuf = addrs.pubhash->data;
		memcpy(&key_id, kbuf->p, kbuf->len);

		if (!sign1(&key_id, ks, &hash, nHashType, scriptSig))
			goto out;
		if (!bkeys_pubkey_append(ks, &key_id, scriptSig))
			goto out;
		break;

	case TX_SCRIPTHASH:		/* TODO; not supported yet */
	case TX_MULTISIG:
		goto out;

	case TX_NONSTANDARD:		/* unknown script type, cannot sign */
		goto out;
	}

	if (txin->scriptSig)
		cstr_free(txin->scriptSig, true);
	txin->scriptSig = scriptSig;
	scriptSig = NULL;
	rc = true;

out:
	if (scriptSig)
		cstr_free(scriptSig, true);
	bsp_addr_free(&addrs);
	return rc;
}

bool bp_sign_sig(struct bp_keystore *ks, const struct bp_utxo *txFrom,
		 struct bp_tx *txTo, unsigned int nIn,
		 unsigned int flags, int nHashType)
{
	if (!ks || !txFrom || !txFrom->vout ||
	    !txTo || !txTo->vin || nIn >= txTo->vin->len)
		return false;

	struct bp_txin *txin = parr_idx(txTo->vin, nIn);

	if (txin->prevout.n >= txFrom->vout->len)
		return false;
	struct bp_txout *txout = parr_idx(txFrom->vout,
						   txin->prevout.n);

	return bp_script_sign(ks, txout->scriptPubKey, txTo, nIn, nHashType);
}

