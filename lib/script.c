
#include "picocoin-config.h"

#include <ccoin/script.h>
#include <ccoin/serialize.h>

bool bsp_getop(struct bscript_op *op, struct bscript_parser *bp)
{
	if (bp->buf->len == 0)
		return false;			/* EOF */

	unsigned char opcode;
	if (!deser_bytes(&opcode, bp->buf, 1))
		goto err_out;
	op->op = opcode;

	if (!bsp_pushdata_op(opcode)) {
		op->data.p = NULL;
		op->data.len = 0;
		return true;
	}

	uint32_t data_len;

	if (opcode < OP_PUSHDATA1)
		data_len = opcode;
	
	else if (opcode == OP_PUSHDATA1) {
		uint8_t v8;
		if (!deser_bytes(&v8, bp->buf, 1))
			goto err_out;
		data_len = v8;
	}
	else if (opcode == OP_PUSHDATA2) {
		uint16_t v16;
		if (!deser_u16(&v16, bp->buf))
			goto err_out;
		data_len = v16;
	}
	else if (opcode == OP_PUSHDATA4) {
		uint32_t v32;
		if (!deser_u32(&v32, bp->buf))
			goto err_out;
		data_len = v32;
	}

	op->data.p = bp->buf->p;
	op->data.len = data_len;

	if (!deser_skip(bp->buf, data_len))
		goto err_out;

	return true;

err_out:
	bp->error = true;
	return false;
}

