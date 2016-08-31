
#include "picocoin-config.h"

#define _GNU_SOURCE			/* for memmem */
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <ccoin/script.h>
#include <ccoin/util.h>
#include <ccoin/key.h>
#include <ccoin/serialize.h>
#include <ccoin/compat.h>		/* for parr_new */
#include <ccoin/crypto/sha1.h>
#include <ccoin/crypto/sha2.h>
#include <ccoin/crypto/ripemd160.h>

static const size_t nDefaultMaxNumSize = 4;

static void string_find_del(cstring *s, const struct buffer *buf)
{
	/* wrap buffer in a script */
	cstring *script = cstr_new_sz(buf->len + 8);
	bsp_push_data(script, buf->p, buf->len);

	/* search for script, as a substring of 's' */
	void *p;
	unsigned int sublen = script->len;
	while ((p = memmem(s->str, s->len, script->str, sublen)) != NULL) {
		void *begin = s->str;
		void *end = begin + s->len;
		void *tail = p + sublen;
		unsigned int tail_len = end - tail;
		unsigned int new_len = s->len - sublen;

		memmove(p, tail, tail_len);
		cstr_resize(s, new_len);
	}

	cstr_free(script, true);
}

static void bp_tx_calc_sighash(bu256_t *hash, const struct bp_tx *tx,
			       int nHashType)
{
	/* TODO: introduce hashing-only serialization mode */

	cstring *s = cstr_new_sz(512);
	ser_bp_tx(s, tx);
	ser_s32(s, nHashType);

	bu_Hash((unsigned char *) hash, s->str, s->len);

	cstr_free(s, true);
}

void bp_tx_sighash(bu256_t *hash, const cstring *scriptCode,
		   const struct bp_tx *txTo, unsigned int nIn,
		   int nHashType)
{
	if (nIn >= txTo->vin->len) {
		bu256_set_u64(hash, 1);
		return;
	}

	// Check for invalid use of SIGHASH_SINGLE
	if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
		if (nIn >= txTo->vin->len) {
			bu256_set_u64(hash, 1);
			return;
		}
	}

	struct bp_tx txTmp;
	bp_tx_init(&txTmp);
	bp_tx_copy(&txTmp, txTo);

	/* TODO: find-and-delete OP_CODESEPARATOR from scriptCode */

	/* Blank out other inputs' signatures */
	unsigned int i;
	struct bp_txin *txin;
	for (i = 0; i < txTmp.vin->len; i++) {
		txin = parr_idx(txTmp.vin, i);
		cstr_resize(txin->scriptSig, 0);

		if (i == nIn)
			cstr_append_buf(txin->scriptSig,
					    scriptCode->str, scriptCode->len);
	}

	/* Blank out some of the outputs */
	if ((nHashType & 0x1f) == SIGHASH_NONE) {
		/* Wildcard payee */
		bp_tx_free_vout(&txTmp);
		txTmp.vout = parr_new(1, bp_txout_freep);

		/* Let the others update at will */
		for (i = 0; i < txTmp.vin->len; i++) {
			txin = parr_idx(txTmp.vin, i);
			if (i != nIn)
				txin->nSequence = 0;
		}
	}

	else if ((nHashType & 0x1f) == SIGHASH_SINGLE) {
		/* Only lock-in the txout payee at same index as txin */
		unsigned int nOut = nIn;
		if (nOut >= txTmp.vout->len) {
			bu256_set_u64(hash, 1);
			goto out;
		}

		parr_resize(txTmp.vout, nOut + 1);

		for (i = 0; i < nOut; i++) {
			struct bp_txout *txout;

			txout = parr_idx(txTmp.vout, i);
			bp_txout_set_null(txout);
		}

		/* Let the others update at will */
		for (i = 0; i < txTmp.vin->len; i++) {
			txin = parr_idx(txTmp.vin, i);
			if (i != nIn)
				txin->nSequence = 0;
		}
	}

	/* Blank out other inputs completely;
	   not recommended for open transactions */
	if (nHashType & SIGHASH_ANYONECANPAY) {
		if (nIn > 0)
			parr_remove_range(txTmp.vin, 0, nIn);
		parr_resize(txTmp.vin, 1);
	}

	/* Serialize and hash */
	bp_tx_calc_sighash(hash, &txTmp, nHashType);

out:
	bp_tx_free(&txTmp);
}

static const unsigned char disabled_op[256] = {
	[OP_CAT] = 1,
	[OP_SUBSTR] = 1,
	[OP_LEFT] = 1,
	[OP_RIGHT] = 1,
	[OP_INVERT] = 1,
	[OP_AND] = 1,
	[OP_OR] = 1,
	[OP_XOR] = 1,
	[OP_2MUL] = 1,
	[OP_2DIV] = 1,
	[OP_MUL] = 1,
	[OP_DIV] = 1,
	[OP_MOD] = 1,
	[OP_LSHIFT] = 1,
	[OP_RSHIFT] = 1,
};

static bool CastToBigNum(mpz_t vo, const struct buffer *buf, bool fRequireMinimal, const size_t nMaxNumSize)
{
	if (buf->len > nMaxNumSize)
		return false;

	const unsigned char *vch = buf->p;

	if (fRequireMinimal && buf->len > 0) {
		// Check that the number is encoded with the minimum possible
		// number of bytes.
		//
		// If the most-significant-byte - excluding the sign bit - is zero
		// then we're not minimal. Note how this test also rejects the
		// negative-zero encoding, 0x80.
		if ((vch[buf->len - 1] & 0x7f) == 0) {
			// One exception: if there's more than one byte and the most
			// significant bit of the second-most-significant-byte is set
			// it would conflict with the sign bit. An example of this case
			// is +-255, which encode to 0xff00 and 0xff80 respectively.
			// (big-endian).
			if (buf->len <= 1 || (vch[buf->len - 2] & 0x80) == 0) {
				return false;
			}
		}
	}
	bn_setvch(vo, buf->p, buf->len);

	return true;
}

static bool CastToBool(const struct buffer *buf)
{
	unsigned int i;
	const unsigned char *vch = buf->p;
	for (i = 0; i < buf->len; i++) {
		if (vch[i] != 0) {
			// Can be negative zero
			if (i == (buf->len - 1) && vch[i] == 0x80)
				return false;
			return true;
		}
	}
	return false;
}

static void stack_insert(parr *stack, const struct buffer *buf, int index_)
{
	int index = stack->len + index_;
	parr_add(stack, NULL);
	memmove(&stack->data[index + 1], &stack->data[index],
		sizeof(void *) * (stack->len - index - 1));
	stack->data[index] = buffer_copy(buf->p, buf->len);
}

static void stack_push(parr *stack, const struct buffer *buf)
{
	parr_add(stack, buffer_copy(buf->p, buf->len));
}

static void stack_push_nocopy(parr *stack, struct buffer *buf)
{
	parr_add(stack, buf);
}

static void stack_push_char(parr *stack, unsigned char ch)
{
	parr_add(stack, buffer_copy(&ch, 1));
}

static void stack_push_str(parr *stack, cstring *s)
{
	parr_add(stack, buffer_copy(s->str, s->len));
	cstr_free(s, true);
}

static void stack_copy(parr *dest, const parr *src)
{
	unsigned int i;
	for (i = 0; i < src->len; i++)
		stack_push(dest, parr_idx(src, i));
}

static struct buffer *stacktop(parr *stack, int index)
{
	return stack->data[stack->len + index];
}

static int stackint(parr *stack, int index, bool fRequireMinimal)
{
	struct buffer *buf = stacktop(stack, index);
	mpz_t bn;
	mpz_init(bn);

	int ret = -1;

	if (!CastToBigNum(bn, buf, fRequireMinimal, nDefaultMaxNumSize))
		goto out;

	ret = mpz_get_si(bn);

out:
	mpz_clear(bn);
	return ret;
}

static struct buffer *stack_take(parr *stack, int index)
{
	struct buffer *ret = stack->data[stack->len + index];
	stack->data[stack->len + index] = NULL;
	return ret;
}

static void popstack(parr *stack)
{
	assert(stack->len > 0);
	parr_remove_idx(stack, stack->len - 1);
}

static void stack_swap(parr *stack, int idx1, int idx2)
{
	int len = stack->len;
	struct buffer *tmp = stack->data[len + idx1];
	stack->data[len + idx1] = stack->data[len + idx2];
	stack->data[len + idx2] = tmp;
}

static unsigned int count_false(cstring *vfExec)
{
	unsigned int i, count = 0;

	for (i = 0; i < vfExec->len; i++)
		if (vfExec->str[i] == 0)
			count++;

	return count;
}

static bool bp_checksig(const struct buffer *vchSigHT,
			const struct buffer *vchPubKey,
			const cstring *scriptCode,
			const struct bp_tx *txTo, unsigned int nIn,
			int nHashType)
{
	if (!vchSigHT || !vchPubKey || !scriptCode || !txTo ||
	    !vchSigHT->len || !vchPubKey->len || !scriptCode->len)
		return false;

	/* examine hashtype at end of string, then remove it */
	unsigned char *vch_back = vchSigHT->p + (vchSigHT->len - 1);
	if (nHashType == 0)
		nHashType = *vch_back;
	else if (nHashType != *vch_back)
		return false;
	struct buffer vchSig = { vchSigHT->p, vchSigHT->len - 1 };

	/* calculate signature hash of transaction */
	bu256_t sighash;
	bp_tx_sighash(&sighash, scriptCode, txTo, nIn, nHashType);

	/* verify signature hash */
	struct bp_key key;
	bp_key_init(&key);

	bool rc = false;
	if (!bp_pubkey_set(&key, vchPubKey->p, vchPubKey->len))
		goto out;
	if (!bp_verify(&key, &sighash, sizeof(sighash), vchSig.p, vchSig.len))
		goto out;

	rc = true;

out:
	bp_key_free(&key);
	return rc;
}

bool static IsCompressedOrUncompressedPubKey(const struct buffer *vchPubKey) {

    const unsigned char *pubkey = vchPubKey->p;

    if (vchPubKey->len < 33) {
		//  Non-canonical public key: too short
		return false;
    }
    if (pubkey[0] == 0x04) {
		if (vchPubKey->len != 65) {
			//  Non-canonical public key: invalid length for uncompressed key
			return false;
		}
	} else if (pubkey[0] == 0x02 || pubkey[0] == 0x03) {
		if (vchPubKey->len != 33) {
			//  Non-canonical public key: invalid length for compressed key
			return false;
		}
	} else {
		//  Non-canonical public key: neither compressed nor uncompressed
		return false;
    }
    return true;
}

static bool IsValidSignatureEncoding(const struct buffer *vch)
{
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    const unsigned char *sig = vch->p;

    // Minimum and maximum size constraints.
    if (vch->len < 9) return false;
    if (vch->len > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != vch->len - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= vch->len) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)(lenR + lenS + 7) != vch->len) return false;

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

static bool IsLowDERSignature(const struct buffer *vchSig) {
    if (!IsValidSignatureEncoding(vchSig)) return false;

    if (!bp_pubkey_checklowS(vchSig->p, vchSig->len)) return false;

    return true;
}

bool static IsDefinedHashtypeSignature(const struct buffer *vchSig) {
	if (vchSig->len == 0)
		return false;

	const unsigned char *sig = vchSig->p;

    unsigned char nHashType = sig[vchSig->len - 1] & (~(SIGHASH_ANYONECANPAY));

    if (nHashType < SIGHASH_ALL || nHashType > SIGHASH_SINGLE)
        return false;

    return true;
}

static bool CheckSignatureEncoding(const struct buffer *vchSig, unsigned int flags) {
    // Empty signature. Not strictly DER encoded, but allowed to provide a
    // compact way to provide an invalid signature for use with CHECK(MULTI)SIG
    if (vchSig->len == 0)
        return true;

	if ((flags & (SCRIPT_VERIFY_DERSIG | SCRIPT_VERIFY_LOW_S | SCRIPT_VERIFY_STRICTENC)) != 0 && !IsValidSignatureEncoding(vchSig))
		return false;
    else if ((flags & SCRIPT_VERIFY_LOW_S) != 0 && !IsLowDERSignature(vchSig))
		return false;
	else if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsDefinedHashtypeSignature(vchSig))

        return false;
    return true;
}

static bool CheckPubKeyEncoding(const struct buffer *vchPubKey, unsigned int flags) {
    if ((flags & SCRIPT_VERIFY_STRICTENC) != 0 && !IsCompressedOrUncompressedPubKey(vchPubKey))
        return false;

    return true;
}

bool static CheckMinimalPush(struct const_buffer *data, enum opcodetype opcode) {

	const unsigned char *vch = data->p;

	if (data->len == 0) {
		// Could have used OP_0.
		return opcode == OP_0;
	} else if (data->len == 1 && vch[0] >= 1 && vch[0] <= 16) {
		// Could have used OP_1 .. OP_16.
		return opcode == OP_1 + (vch[0] - 1);
	} else if (data->len == 1 && vch[0] == 0x81) {
		// Could have used OP_1NEGATE.
		return opcode == OP_1NEGATE;
	} else if (data->len <= 75) {
		// Could have used a direct push (opcode indicating number of bytes pushed + those bytes).
		return opcode == data->len;
	} else if (data->len <= 255) {
		// Could have used OP_PUSHDATA.
		return opcode == OP_PUSHDATA1;
	} else if (data->len <= 65535) {
		// Could have used OP_PUSHDATA2.
		return opcode == OP_PUSHDATA2;
	}
    return true;
}

bool CheckLockTime(const unsigned int nLockTime, const struct bp_tx *txTo, unsigned int nIn)
{
	// There are two kinds of nLockTime: lock-by-blockheight
	// and lock-by-blocktime, distinguished by whether
	// nLockTime < LOCKTIME_THRESHOLD.
	//
	// We want to compare apples to apples, so fail the script
	// unless the type of nLockTime being tested is the same as
	// the nLockTime in the transaction.
	if (!(
		(txTo->nLockTime <  LOCKTIME_THRESHOLD && nLockTime <  LOCKTIME_THRESHOLD) ||
		(txTo->nLockTime >= LOCKTIME_THRESHOLD && nLockTime >= LOCKTIME_THRESHOLD)
	))
		return false;

	// Now that we know we're comparing apples-to-apples, the
	// comparison is a simple numeric one.
	if (nLockTime > (int64_t)txTo->nLockTime)
		return false;

	// Finally the nLockTime feature can be disabled and thus
	// CHECKLOCKTIMEVERIFY bypassed if every txin has been
	// finalized by setting nSequence to maxint. The
	// transaction would be allowed into the blockchain, making
	// the opcode ineffective.
	//
	// Testing if this vin is not final is sufficient to
	// prevent this condition. Alternatively we could test all
	// inputs, but testing just this input minimizes the data
	// required to prove correct CHECKLOCKTIMEVERIFY execution.
	struct bp_txin *txin = parr_idx(txTo->vin, nIn);

	if (SEQUENCE_FINAL == txin->nSequence)
		return false;

	return true;
}

bool CheckSequence(const unsigned int nSequence, const struct bp_tx *txTo, unsigned int nIn)
{
	const struct bp_txin *txin = parr_idx(txTo->vin, nIn);

	// Relative lock times are supported by comparing the passed
	// in operand to the sequence number of the input.
	const int64_t txToSequence = (int64_t)txin->nSequence;

	// Fail if the transaction's version number is not set high
	// enough to trigger BIP 68 rules.
	if (txTo->nVersion < 2)
		return false;

	// Sequence numbers with their most significant bit set are not
	// consensus constrained. Testing that the transaction's sequence
	// number do not have this bit set prevents using this property
	// to get around a CHECKSEQUENCEVERIFY check.
	if (txToSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG)
		return false;

	// Mask off any bits that do not have consensus-enforced meaning
	// before doing the integer comparisons
	const uint32_t nLockTimeMask = SEQUENCE_LOCKTIME_TYPE_FLAG | SEQUENCE_LOCKTIME_MASK;
	const int64_t txToSequenceMasked = txToSequence & nLockTimeMask;
	const uint64_t nSequenceMasked = nSequence & nLockTimeMask;

	// There are two kinds of nSequence: lock-by-blockheight
	// and lock-by-blocktime, distinguished by whether
	// nSequenceMasked < CTxIn::SEQUENCE_LOCKTIME_TYPE_FLAG.
	//
	// We want to compare apples to apples, so fail the script
	// unless the type of nSequenceMasked being tested is the same as
	// the nSequenceMasked in the transaction.
	if (!(
		(txToSequenceMasked <  SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked <  SEQUENCE_LOCKTIME_TYPE_FLAG) ||
		(txToSequenceMasked >= SEQUENCE_LOCKTIME_TYPE_FLAG && nSequenceMasked >= SEQUENCE_LOCKTIME_TYPE_FLAG)
	)) {
		return false;
	}

	// Now that we know we're comparing apples-to-apples, the
	// comparison is a simple numeric one.
	if (nSequenceMasked > txToSequenceMasked)
		return false;

	return true;
}

static bool bp_script_eval(parr *stack, const cstring *script,
			   const struct bp_tx *txTo, unsigned int nIn,
			   unsigned int flags, int nHashType)
{
	struct const_buffer pc = { script->str, script->len };
	struct const_buffer pend = { script->str + script->len, 0 };
	struct const_buffer pbegincodehash = { script->str, script->len };
	struct bscript_op op;
	bool rc = false;
	cstring *vfExec = cstr_new(NULL);
	parr *altstack = parr_new(0, buffer_freep);
	mpz_t bn;
	mpz_init(bn);

	if (script->len > MAX_SCRIPT_SIZE)
		goto out;

	unsigned int nOpCount = 0;
	bool fRequireMinimal = (flags & SCRIPT_VERIFY_MINIMALDATA) != 0;

	struct bscript_parser bp;
	bsp_start(&bp, &pc);

	while (pc.p < pend.p) {
		bool fExec = !count_false(vfExec);

		if (!bsp_getop(&op, &bp))
			goto out;
		enum opcodetype opcode = op.op;

		if (op.data.len > MAX_SCRIPT_ELEMENT_SIZE)
			goto out;
		if (opcode > OP_16 && ++nOpCount > MAX_OPS_PER_SCRIPT)
			goto out;
		if (disabled_op[opcode])
			goto out;

		if (fExec && is_bsp_pushdata(opcode)) {
			if (fRequireMinimal && !CheckMinimalPush(&op.data, opcode))
				goto out;
			stack_push(stack, (struct buffer *) &op.data);
		} else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
		switch (opcode) {

		//
		// Push value
		//
		case OP_1NEGATE:
		case OP_1:
		case OP_2:
		case OP_3:
		case OP_4:
		case OP_5:
		case OP_6:
		case OP_7:
		case OP_8:
		case OP_9:
		case OP_10:
		case OP_11:
		case OP_12:
		case OP_13:
		case OP_14:
		case OP_15:
		case OP_16:
			mpz_set_si(bn, (int)opcode - (int)(OP_1 - 1));
			stack_push_str(stack, bn_getvch(bn));
			break;

		//
		// Control
		//
		case OP_NOP:
			break;

		case OP_CHECKLOCKTIMEVERIFY: {
			if (!(flags & SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY)) {
				// not enabled; treat as a NOP2
				if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
					goto out;
				break;
			}

			if (stack->len < 1)
				goto out;

			// Note that elsewhere numeric opcodes are limited to
			// operands in the range -2**31+1 to 2**31-1, however it is
			// legal for opcodes to produce results exceeding that
			// range. This limitation is implemented by CastToBigNum's
			// default 4-byte limit.
			//
			// If we kept to that limit we'd have a year 2038 problem,
			// even though the nLockTime field in transactions
			// themselves is uint32 which only becomes meaningless
			// after the year 2106.
			//
			// Thus as a special case we tell CastToBigNum to accept up
			// to 5-byte bignums, which are good until 2**39-1, well
			// beyond the 2**32-1 limit of the nLockTime field itself.

			if (!CastToBigNum(bn, stacktop(stack, -1), fRequireMinimal, 5))
				goto out;

			// In the rare event that the argument may be < 0 due to
			// some arithmetic being done first, you can always use
			// 0 MAX CHECKLOCKTIMEVERIFY.
			if (mpz_sgn(bn) < 0)
				goto out;

			uint64_t nLockTime = mpz_get_ui(bn);

			// Actually compare the specified lock time with the transaction.
			if (!CheckLockTime(nLockTime, txTo, nIn))
				goto out;

			break;
		}

		case OP_CHECKSEQUENCEVERIFY:
		{
			if (!(flags & SCRIPT_VERIFY_CHECKSEQUENCEVERIFY)) {
				// not enabled; treat as a NOP3
				if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
					goto out;
				break;
			}

			if (stack->len < 1)
				goto out;

			// nSequence, like nLockTime, is a 32-bit unsigned integer
			// field. See the comment in CHECKLOCKTIMEVERIFY regarding
			// 5-byte numeric operands.
			if (!CastToBigNum(bn, stacktop(stack, -1), fRequireMinimal, 5))
				goto out;

			// In the rare event that the argument may be < 0 due to
			// some arithmetic being done first, you can always use
			// 0 MAX CHECKSEQUENCEVERIFY.
			if (mpz_sgn(bn) < 0)
				goto out;

			uint64_t nSequence = mpz_get_ui(bn);

			// To provide for future soft-fork extensibility, if the
			// operand has the disabled lock-time flag set,
			// CHECKSEQUENCEVERIFY behaves as a NOP.
			if ((nSequence & SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0)
				break;

			// Compare the specified sequence number with the input.
			if (!CheckSequence(nSequence, txTo, nIn))
				goto out;

			break;
		}

		case OP_NOP1: case OP_NOP4: case OP_NOP5:
		case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case OP_NOP10:
			if (flags & SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS)
				goto out;
			break;

		case OP_IF:
		case OP_NOTIF: {
			// <expression> if [statements] [else [statements]] endif
			bool fValue = false;
			if (fExec) {
				if (stack->len < 1)
					goto out;
				struct buffer *vch = stacktop(stack, -1);
				fValue = CastToBool(vch);
				if (opcode == OP_NOTIF)
					fValue = !fValue;
				popstack(stack);
			}
			uint8_t vc = (uint8_t) fValue;
			cstr_append_c(vfExec, vc);
			break;
		}

		case OP_ELSE: {
			if (vfExec->len == 0)
				goto out;
			uint8_t *v = (uint8_t *) &vfExec->str[vfExec->len - 1];
			*v = !(*v);
			break;
		}

		case OP_ENDIF:
			if (vfExec->len == 0)
				goto out;
			cstr_erase(vfExec, vfExec->len - 1, 1);
			break;

		case OP_VERIFY: {
			if (stack->len < 1)
				goto out;
			bool fValue = CastToBool(stacktop(stack, -1));
			if (fValue)
				popstack(stack);
			else
				goto out;
			break;
		}

		case OP_RETURN:
			goto out;

		//
		// Stack ops
		//
		case OP_TOALTSTACK:
			if (stack->len < 1)
				goto out;
			stack_push(altstack, stacktop(stack, -1));
			popstack(stack);
			break;

		case OP_FROMALTSTACK:
			if (altstack->len < 1)
				goto out;
			stack_push(stack, stacktop(altstack, -1));
			popstack(altstack);
			break;

		case OP_2DROP:
			// (x1 x2 -- )
			if (stack->len < 2)
				goto out;
			popstack(stack);
			popstack(stack);
			break;

		case OP_2DUP: {
			// (x1 x2 -- x1 x2 x1 x2)
			if (stack->len < 2)
				goto out;
			struct buffer *vch1 = stacktop(stack, -2);
			struct buffer *vch2 = stacktop(stack, -1);
			stack_push(stack, vch1);
			stack_push(stack, vch2);
			break;
		}

		case OP_3DUP: {
			// (x1 x2 x3 -- x1 x2 x3 x1 x2 x3)
			if (stack->len < 3)
				goto out;
			struct buffer *vch1 = stacktop(stack, -3);
			struct buffer *vch2 = stacktop(stack, -2);
			struct buffer *vch3 = stacktop(stack, -1);
			stack_push(stack, vch1);
			stack_push(stack, vch2);
			stack_push(stack, vch3);
			break;
		}

		case OP_2OVER: {
			// (x1 x2 x3 x4 -- x1 x2 x3 x4 x1 x2)
			if (stack->len < 4)
				goto out;
			struct buffer *vch1 = stacktop(stack, -4);
			struct buffer *vch2 = stacktop(stack, -3);
			stack_push(stack, vch1);
			stack_push(stack, vch2);
			break;
		}

		case OP_2ROT: {
			// (x1 x2 x3 x4 x5 x6 -- x3 x4 x5 x6 x1 x2)
			if (stack->len < 6)
				goto out;
			struct buffer *vch1 = stack_take(stack, -6);
			struct buffer *vch2 = stack_take(stack, -5);
			parr_remove_range(stack, stack->len - 6, 2);
			stack_push_nocopy(stack, vch1);
			stack_push_nocopy(stack, vch2);
			break;
		}

		case OP_2SWAP:
			// (x1 x2 x3 x4 -- x3 x4 x1 x2)
			if (stack->len < 4)
				goto out;
			stack_swap(stack, -4, -2);
			stack_swap(stack, -3, -1);
			break;

		case OP_IFDUP: {
			// (x - 0 | x x)
			if (stack->len < 1)
				goto out;
			struct buffer *vch = stacktop(stack, -1);
			if (CastToBool(vch))
				stack_push(stack, vch);
			break;
		}

		case OP_DEPTH:
			// -- stacksize
			mpz_set_ui(bn, stack->len);
			stack_push_str(stack, bn_getvch(bn));
			break;

		case OP_DROP:
			// (x -- )
			if (stack->len < 1)
				goto out;
			popstack(stack);
			break;

		case OP_DUP: {
			// (x -- x x)
			if (stack->len < 1)
				goto out;
			struct buffer *vch = stacktop(stack, -1);
			stack_push(stack, vch);
			break;
		}

		case OP_NIP:
			// (x1 x2 -- x2)
			if (stack->len < 2)
				goto out;
			parr_remove_idx(stack, stack->len - 2);
			break;

		case OP_OVER: {
			// (x1 x2 -- x1 x2 x1)
			if (stack->len < 2)
				goto out;
			struct buffer *vch = stacktop(stack, -2);
			stack_push(stack, vch);
			break;
		}

		case OP_PICK:
		case OP_ROLL: {
			// (xn ... x2 x1 x0 n - xn ... x2 x1 x0 xn)
			// (xn ... x2 x1 x0 n - ... x2 x1 x0 xn)
			if (stack->len < 2)
				goto out;

			int n = stackint(stack, -1, fRequireMinimal);
			popstack(stack);
			if (n < 0 || n >= (int)stack->len)
				goto out;
			struct buffer *vch = stacktop(stack, -n-1);
			if (opcode == OP_ROLL) {
				vch = buffer_copy(vch->p, vch->len);
				parr_remove_idx(stack,
							 stack->len - n - 1);
				stack_push_nocopy(stack, vch);
			} else
				stack_push(stack, vch);
			break;
		}

		case OP_ROT: {
			// (x1 x2 x3 -- x2 x3 x1)
			//  x2 x1 x3  after first swap
			//  x2 x3 x1  after second swap
			if (stack->len < 3)
				goto out;
			stack_swap(stack, -3, -2);
			stack_swap(stack, -2, -1);
			break;
		}

		case OP_SWAP: {
			// (x1 x2 -- x2 x1)
			if (stack->len < 2)
				goto out;
			stack_swap(stack, -2, -1);
			break;
		}

		case OP_TUCK: {
			// (x1 x2 -- x2 x1 x2)
			if (stack->len < 2)
				goto out;
			struct buffer *vch = stacktop(stack, -1);
			stack_insert(stack, vch, -2);
			break;
		}

		case OP_SIZE: {
			// (in -- in size)
			if (stack->len < 1)
				goto out;
			struct buffer *vch = stacktop(stack, -1);
			mpz_set_ui(bn, vch->len);
			stack_push_str(stack, bn_getvch(bn));
			break;
		}


		case OP_EQUAL:
		case OP_EQUALVERIFY: {
			// (x1 x2 - bool)
			if (stack->len < 2)
				goto out;
			struct buffer *vch1 = stacktop(stack, -2);
			struct buffer *vch2 = stacktop(stack, -1);
			bool fEqual = buffer_equal(vch1, vch2);
			// OP_NOTEQUAL is disabled because it would be too easy to say
			// something like n != 1 and have some wiseguy pass in 1 with extra
			// zero bytes after it (numerically, 0x01 == 0x0001 == 0x000001)
			//if (opcode == OP_NOTEQUAL)
			//	fEqual = !fEqual;
			popstack(stack);
			popstack(stack);
			stack_push_char(stack, fEqual ? 1 : 0);
			if (opcode == OP_EQUALVERIFY) {
				if (fEqual)
					popstack(stack);
				else
					goto out;
			}
			break;
		}

		//
		// Numeric
		//
		case OP_1ADD:
		case OP_1SUB:
		case OP_NEGATE:
		case OP_ABS:
		case OP_NOT:
		case OP_0NOTEQUAL: {
			// (in -- out)
			if (stack->len < 1)
				goto out;
			if (!CastToBigNum(bn, stacktop(stack, -1), fRequireMinimal, nDefaultMaxNumSize))
				goto out;
			switch (opcode)
			{
			case OP_1ADD:
				mpz_add_ui(bn, bn, 1);
				break;
			case OP_1SUB:
				mpz_sub_ui(bn, bn, 1);
				break;
			case OP_NEGATE:
				mpz_neg(bn, bn);
				break;
			case OP_ABS:
				mpz_abs(bn, bn);
				break;
			case OP_NOT:
				mpz_set_ui(bn, mpz_sgn(bn) == 0 ? 1 : 0);
				break;
			case OP_0NOTEQUAL:
				mpz_set_ui(bn, mpz_sgn(bn) == 0 ? 0 : 1);
				break;
			default:
				// impossible
				goto out;
			}
			popstack(stack);
			stack_push_str(stack, bn_getvch(bn));
			break;
		}

		case OP_ADD:
		case OP_SUB:
		case OP_BOOLAND:
		case OP_BOOLOR:
		case OP_NUMEQUAL:
		case OP_NUMEQUALVERIFY:
		case OP_NUMNOTEQUAL:
		case OP_LESSTHAN:
		case OP_GREATERTHAN:
		case OP_LESSTHANOREQUAL:
		case OP_GREATERTHANOREQUAL:
		case OP_MIN:
		case OP_MAX: {
			// (x1 x2 -- out)
			if (stack->len < 2)
				goto out;

			mpz_t bn1, bn2;
			mpz_init(bn1);
			mpz_init(bn2);
			if (!CastToBigNum(bn1, stacktop(stack, -2), fRequireMinimal, nDefaultMaxNumSize) ||
			    !CastToBigNum(bn2, stacktop(stack, -1), fRequireMinimal, nDefaultMaxNumSize)) {
				mpz_clear(bn1);
				mpz_clear(bn2);
				goto out;
			}

			switch (opcode)
			{
			case OP_ADD:
				mpz_add(bn, bn1, bn2);
				break;
			case OP_SUB:
				mpz_sub(bn, bn1, bn2);
				break;
			case OP_BOOLAND:
				mpz_set_ui(bn,
				    !(mpz_sgn(bn1) == 0) && !(mpz_sgn(bn2) == 0) ?
				    1 : 0);
				break;
			case OP_BOOLOR:
				mpz_set_ui(bn,
				    !(mpz_sgn(bn1) == 0) || !(mpz_sgn(bn2) == 0) ?
				    1 : 0);
				break;
			case OP_NUMEQUAL:
			case OP_NUMEQUALVERIFY:
				mpz_set_ui(bn,
				    mpz_cmp(bn1, bn2) == 0 ?  1 : 0);
				break;
			case OP_NUMNOTEQUAL:
				mpz_set_ui(bn,
				    mpz_cmp(bn1, bn2) != 0 ?  1 : 0);
				break;
			case OP_LESSTHAN:
				mpz_set_ui(bn,
				    mpz_cmp(bn1, bn2) < 0 ?  1 : 0);
				break;
			case OP_GREATERTHAN:
				mpz_set_ui(bn,
				    mpz_cmp(bn1, bn2) > 0 ?  1 : 0);
				break;
			case OP_LESSTHANOREQUAL:
				mpz_set_ui(bn,
				    mpz_cmp(bn1, bn2) <= 0 ?  1 : 0);
				break;
			case OP_GREATERTHANOREQUAL:
				mpz_set_ui(bn,
				    mpz_cmp(bn1, bn2) >= 0 ?  1 : 0);
				break;
			case OP_MIN:
				if (mpz_cmp(bn1, bn2) < 0)
					mpz_set(bn, bn1);
				else
					mpz_set(bn, bn2);
				break;
			case OP_MAX:
				if (mpz_cmp(bn1, bn2) > 0)
					mpz_set(bn, bn1);
				else
					mpz_set(bn, bn2);
				break;
			default:
				// impossible
				break;
			}
			popstack(stack);
			popstack(stack);
			stack_push_str(stack, bn_getvch(bn));
			mpz_clear(bn1);
			mpz_clear(bn2);

			if (opcode == OP_NUMEQUALVERIFY)
			{
				if (CastToBool(stacktop(stack, -1)))
					popstack(stack);
				else
					goto out;
			}
			break;
		}

		case OP_WITHIN: {
			// (x min max -- out)
			if (stack->len < 3)
				goto out;
			mpz_t bn1, bn2, bn3;
			mpz_init(bn1);
			mpz_init(bn2);
			mpz_init(bn3);
			bool rc1 = CastToBigNum(bn1, stacktop(stack, -3), fRequireMinimal, nDefaultMaxNumSize);
			bool rc2 = CastToBigNum(bn2, stacktop(stack, -2), fRequireMinimal, nDefaultMaxNumSize);
			bool rc3 = CastToBigNum(bn3, stacktop(stack, -1), fRequireMinimal, nDefaultMaxNumSize);
			bool fValue = (mpz_cmp(bn2, bn1) <= 0 &&
				       mpz_cmp(bn1, bn3) < 0);
			popstack(stack);
			popstack(stack);
			popstack(stack);
			stack_push_char(stack, fValue ? 1 : 0);
			mpz_clear(bn1);
			mpz_clear(bn2);
			mpz_clear(bn3);
			if (!rc1 || !rc2 || !rc3)
				goto out;
			break;
		}

		//
		// Crypto
		//
		case OP_RIPEMD160:
		case OP_SHA1:
		case OP_SHA256:
		case OP_HASH160:
		case OP_HASH256: {
			// (in -- hash)
			if (stack->len < 1)
				goto out;
			struct buffer *vch = stacktop(stack, -1);
			unsigned int hashlen;
			unsigned char md[32];

			switch (opcode) {
			case OP_RIPEMD160:
				hashlen = 20;
				ripemd160(vch->p, vch->len, md);
				break;
			case OP_SHA1:
				hashlen = 20;
				sha1_Raw(vch->p, vch->len, md);
				break;
			case OP_SHA256:
				hashlen = 32;
				sha256_Raw(vch->p, vch->len, md);
				break;
			case OP_HASH160:
				hashlen = 20;
				bu_Hash160(md, vch->p, vch->len);
				break;
			case OP_HASH256:
				hashlen = 32;
				bu_Hash(md, vch->p, vch->len);
				break;
			default:
				// impossible
				goto out;
			}

			popstack(stack);
			struct buffer buf = { md, hashlen };
			stack_push(stack, &buf);
			break;
		}

		case OP_CODESEPARATOR:
			// Hash starts after the code separator
			memcpy(&pbegincodehash, &pc, sizeof(pc));
			break;

		case OP_CHECKSIG:
		case OP_CHECKSIGVERIFY: {
			// (sig pubkey -- bool)
			if (stack->len < 2)
				goto out;

			struct buffer *vchSig	= stacktop(stack, -2);
			struct buffer *vchPubKey = stacktop(stack, -1);

			////// debug print
			//PrintHex(vchSig.begin(), vchSig.end(), "sig: %s\n");
			//PrintHex(vchPubKey.begin(), vchPubKey.end(), "pubkey: %s\n");

			// Subset of script starting at the most recent codeseparator
			cstring *scriptCode = cstr_new_sz(pbegincodehash.len);
			cstr_append_buf(scriptCode,
					    pbegincodehash.p,
					    pbegincodehash.len);

			// Drop the signature, since there's no way for
			// a signature to sign itself
			string_find_del(scriptCode, vchSig);

			if (!CheckSignatureEncoding(vchSig, flags) || !CheckPubKeyEncoding(vchPubKey, flags)) {
				cstr_free(scriptCode, true);
				goto out;
			}

			bool fSuccess = bp_checksig(vchSig, vchPubKey,
						       scriptCode,
						       txTo, nIn, nHashType);

			cstr_free(scriptCode, true);

			popstack(stack);
			popstack(stack);
			stack_push_char(stack, fSuccess ? 1 : 0);
			if (opcode == OP_CHECKSIGVERIFY)
			{
				if (fSuccess)
					popstack(stack);
				else
					goto out;
			}
			break;
		}

		case OP_CHECKMULTISIG:
		case OP_CHECKMULTISIGVERIFY: {
			// ([sig ...] num_of_signatures [pubkey ...] num_of_pubkeys -- bool)

			int i = 1;
			if ((int)stack->len < i)
				goto out;

			int nKeysCount = stackint(stack, -i, fRequireMinimal);
			if (nKeysCount < 0 || nKeysCount > MAX_PUBKEYS_PER_MULTISIG)
				goto out;
			nOpCount += nKeysCount;
			if (nOpCount > MAX_OPS_PER_SCRIPT)
				goto out;
			int ikey = ++i;
			i += nKeysCount;
			if ((int)stack->len < i)
				goto out;

			int nSigsCount = stackint(stack, -i, fRequireMinimal);
			if (nSigsCount < 0 || nSigsCount > nKeysCount)
				goto out;
			int isig = ++i;
			i += nSigsCount;
			if ((int)stack->len < i)
				goto out;

			// Subset of script starting at the most recent codeseparator
			cstring *scriptCode = cstr_new_sz(pbegincodehash.len);
			cstr_append_buf(scriptCode,
					    pbegincodehash.p,
					    pbegincodehash.len);

			// Drop the signatures, since there's no way for
			// a signature to sign itself
			int k;
			for (k = 0; k < nSigsCount; k++)
			{
				struct buffer *vchSig =stacktop(stack, -isig-k);
				string_find_del(scriptCode, vchSig);
			}

			bool fSuccess = true;
			while (fSuccess && nSigsCount > 0)
			{
				struct buffer *vchSig	= stacktop(stack, -isig);
				struct buffer *vchPubKey = stacktop(stack, -ikey);

				// Check signature
				if (!CheckSignatureEncoding(vchSig, flags) || !CheckPubKeyEncoding(vchPubKey, flags)) {
					cstr_free(scriptCode, true);
					goto out;
				}

				bool fOk = bp_checksig(vchSig, vchPubKey,
							  scriptCode, txTo, nIn,
							  nHashType);

				if (fOk) {
					isig++;
					nSigsCount--;
				}
				ikey++;
				nKeysCount--;

				// If there are more signatures left than keys left,
				// then too many signatures have failed
				if (nSigsCount > nKeysCount)
					fSuccess = false;
			}

			cstr_free(scriptCode, true);

			while (i-- > 0)
				popstack(stack);
			stack_push_char(stack, fSuccess ? 1 : 0);

			if (opcode == OP_CHECKMULTISIGVERIFY)
			{
				if (fSuccess)
					popstack(stack);
				else
					goto out;
			}
			break;
		}

		default:
			goto out;
		}

		if (stack->len + altstack->len > 1000)
			goto out;
	}

	rc = (vfExec->len == 0 && bp.error == false);

out:
	mpz_clear(bn);
	parr_free(altstack, true);
	cstr_free(vfExec, true);
	return rc;
}

bool bp_script_verify(const cstring *scriptSig, const cstring *scriptPubKey,
		      const struct bp_tx *txTo, unsigned int nIn,
		      unsigned int flags, int nHashType)
{
	bool rc = false;
	parr *stack = parr_new(0, buffer_freep);
	parr *stackCopy = NULL;

	struct const_buffer sigbuf = { scriptSig->str, scriptSig->len };
	if ((flags & SCRIPT_VERIFY_SIGPUSHONLY) != 0 && !is_bsp_pushonly(&sigbuf))
		goto out;

	if (!bp_script_eval(stack, scriptSig, txTo, nIn, flags, nHashType))
		goto out;

	if (flags & SCRIPT_VERIFY_P2SH) {
		stackCopy = parr_new(stack->len, buffer_freep);
		stack_copy(stackCopy, stack);
	}

	if (!bp_script_eval(stack, scriptPubKey, txTo, nIn, flags, nHashType))
		goto out;
	if (stack->len == 0)
		goto out;

	if (CastToBool(stacktop(stack, -1)) == false)
		goto out;

	if ((flags & SCRIPT_VERIFY_P2SH) && is_bsp_p2sh_str(scriptPubKey)) {
		if (!is_bsp_pushonly(&sigbuf))
			goto out;
		if (stackCopy->len < 1)
			goto out;

		struct buffer *pubkey2_buf = stack_take(stackCopy, -1);
		popstack(stackCopy);

		cstring *pubkey2 = cstr_new_buf(pubkey2_buf->p, pubkey2_buf->len);

		buffer_freep(pubkey2_buf);

		bool rc2 = bp_script_eval(stackCopy, pubkey2, txTo, nIn,
					  flags, nHashType);
		cstr_free(pubkey2, true);

		if (!rc2)
			goto out;
		if (stackCopy->len == 0)
			goto out;
		if (CastToBool(stacktop(stackCopy, -1)) == false)
			goto out;
	}
	// The CLEANSTACK check is only performed after potential P2SH evaluation,
	// as the non-P2SH evaluation of a P2SH script will obviously not result in
	// a clean stack (the P2SH inputs remain).
	if ((flags & SCRIPT_VERIFY_CLEANSTACK) != 0) {
		// Disallow CLEANSTACK without P2SH, as otherwise a switch CLEANSTACK->P2SH+CLEANSTACK
		// would be possible, which is not a softfork (and P2SH should be one).
		assert((flags & SCRIPT_VERIFY_P2SH) != 0);
		if (stack->len != 1)
			goto out;
	}

	rc = true;

out:
	parr_free(stack, true);
	if (stackCopy)
		parr_free(stackCopy, true);
	return rc;
}

bool bp_verify_sig(const struct bp_utxo *txFrom, const struct bp_tx *txTo,
		   unsigned int nIn, unsigned int flags, int nHashType)
{
	if (!txFrom || !txFrom->vout || !txFrom->vout->len ||
	    !txTo || !txTo->vin || !txTo->vin->len ||
	    (txTo->vin->len <= nIn))
		return false;

	struct bp_txin *txin = parr_idx(txTo->vin, nIn);
	if (txin->prevout.n >= txFrom->vout->len)
		return false;

	struct bp_txout *txout = parr_idx(txFrom->vout,
						   txin->prevout.n);
	if (!txout)
		return false;

	return bp_script_verify(txin->scriptSig, txout->scriptPubKey,
				txTo, nIn, flags, nHashType);
}
