
#include "picocoin-config.h"

#include <ccoin/script.h>
#include <ccoin/script_eval.h>
#include <ccoin/util.h>

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

static void stack_push(GPtrArray *stack, const struct buffer *buf)
{
	g_ptr_array_add(stack, buffer_copy(buf->p, buf->len));
}

static void stack_push_str(GPtrArray *stack, GString *s)
{
	g_ptr_array_add(stack, buffer_copy(s->str, s->len));
	g_string_free(s, TRUE);
}

static struct buffer *stacktop(GPtrArray *stack, int index)
{
	return stack->pdata[stack->len + index];
}

static struct buffer *stack_take(GPtrArray *stack, int index)
{
	struct buffer *ret = stack->pdata[stack->len + index];
	stack->pdata[stack->len + index] = NULL;
	return ret;
}

static void popstack(GPtrArray *stack)
{
	if (stack->len)
		g_ptr_array_remove_index(stack, stack->len - 1);
}

static void stack_swap(GPtrArray *stack, int idx1, int idx2)
{
	int len = stack->len;
	struct buffer *tmp = stack->pdata[len + idx1];
	stack->pdata[len + idx1] = stack->pdata[len + idx2];
	stack->pdata[len + idx2] = tmp;
}

static unsigned int count_false(GByteArray *vfExec)
{
	unsigned int i, count = 0;

	for (i = 0; i < vfExec->len; i++)
		if (vfExec->data[i] == 0)
			count++;

	return count;
}

static void bn_set_int(BIGNUM *n, int val)
{
	if (val >= 0)
		BN_set_word(n, val);
	else {
		BN_set_word(n, -val);
		BN_set_negative(n, 1);
	}
}

bool bp_script_eval(GPtrArray *stack, const GString *script,
		    const struct bp_tx *txTo, unsigned int nIn,
		    int nHashType)
{
	struct const_buffer pc = { script->str, script->len };
	struct const_buffer pend = { script->str + script->len, 0 };
	struct const_buffer pbegincodehash = { script->str, script->len };
	struct bscript_op op;
	bool rc = false;
	GByteArray *vfExec = g_byte_array_new();
	GPtrArray *altstack = g_ptr_array_new_with_free_func(
						(GDestroyNotify) buffer_free);
	BIGNUM bn;
	BN_init(&bn);

	if (script->len > 10000)
		goto out;
	
	unsigned int nOpCount = 0;

	struct bscript_parser bp;
	bsp_start(&bp, &pc);

	while (pc.p < pend.p) {
		bool fExec = !count_false(vfExec);

		if (!bsp_getop(&op, &bp))
			goto out;
		enum opcodetype opcode = op.op;

		if (op.data.len > 520)
			goto out;
		if (opcode > OP_16 && ++nOpCount > 201)
			goto out;
		if (disabled_op[opcode])
			goto out;

		if (fExec && is_bsp_pushdata(opcode))
			stack_push(stack, (struct buffer *) &op.data);
		else if (fExec || (OP_IF <= opcode && opcode <= OP_ENDIF))
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
			bn_set_int(&bn, (int)opcode - (int)(OP_1 - 1));
			stack_push_str(stack, bn_getvch(&bn));
			break;

		//
		// Control
		//
		case OP_NOP:
		case OP_NOP1: case OP_NOP2: case OP_NOP3: case OP_NOP4: case
OP_NOP5:
		case OP_NOP6: case OP_NOP7: case OP_NOP8: case OP_NOP9: case
OP_NOP10:
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
			guint8 vc = (guint8) fValue;
			g_byte_array_append(vfExec, &vc, 1);
			break;
		}

		case OP_ELSE: {
			if (vfExec->len == 0)
				goto out;
			guint8 *v = &vfExec->data[vfExec->len - 1];
			*v = !(*v);
			break;
		}

		case OP_ENDIF:
			if (vfExec->len == 0)
				goto out;
			g_byte_array_remove_index(vfExec, vfExec->len - 1);
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

		case OP_2DROP: {
			// (x1 x2 -- )
			if (stack->len < 2)
				goto out;
			popstack(stack);
			popstack(stack);
			break;
		}

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
			g_ptr_array_remove_range(stack, stack->len - 6, 2);
			stack_push(stack, vch1);
			stack_push(stack, vch2);
			break;
		}

		case OP_2SWAP: {
			// (x1 x2 x3 x4 -- x3 x4 x1 x2)
			if (stack->len < 4)
				goto out;
			stack_swap(stack, -4, -2);
			stack_swap(stack, -3, -1);
			break;
		}

		case OP_IFDUP: {
			// (x - 0 | x x)
			if (stack->len < 1)
				goto out;
			struct buffer *vch = stacktop(stack, -1);
			if (CastToBool(vch))
				stack_push(stack, vch);
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
	BN_clear_free(&bn);
	g_ptr_array_free(altstack, TRUE);
	g_byte_array_unref(vfExec);
	return rc;
}

