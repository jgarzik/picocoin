
#include "picocoin-config.h"

#include "picocoin.h"
#include "core.h"
#include "coredefs.h"
#include "serialize.h"

bool deser_bp_addr(unsigned int protover,
		struct bp_address *addr, struct buffer *buf)
{
	if (protover >= CADDR_TIME_VERSION)
		if (!deser_u32(&addr->nTime, buf)) return false;
	if (!deser_u64(&addr->nServices, buf)) return false;
	if (!deser_bytes(&addr->ip, buf, 16)) return false;
	if (!deser_u16(&addr->port, buf)) return false;
	return true;
}

void ser_bp_addr(GString *s, unsigned int protover, const struct bp_address *addr)
{
	if (protover >= CADDR_TIME_VERSION) 
		ser_u32(s, addr->nTime);
	ser_u64(s, addr->nServices);
	ser_bytes(s, addr->ip, 16);
	ser_u16(s, addr->port);
}

void bp_outpt_init(struct bp_outpt *outpt)
{
	memset(outpt, 0, sizeof(*outpt));
	BN_init(&outpt->hash);
}

bool deser_bp_outpt(struct bp_outpt *outpt, struct buffer *buf)
{
	if (!deser_u256(&outpt->hash, buf)) return false;
	if (!deser_u32(&outpt->n, buf)) return false;
	return true;
}

void ser_bp_outpt(GString *s, const struct bp_outpt *outpt)
{
	ser_u256(s, &outpt->hash);
	ser_u32(s, outpt->n);
}

void bp_outpt_free(struct bp_outpt *outpt)
{
	BN_clear_free(&outpt->hash);
}

void bp_txin_init(struct bp_txin *txin)
{
	memset(txin, 0, sizeof(*txin));
	bp_outpt_init(&txin->prevout);
}

bool deser_bp_txin(struct bp_txin *txin, struct buffer *buf)
{
	if (!deser_bp_outpt(&txin->prevout, buf)) return false;
	if (!deser_varstr(&txin->scriptSig, buf)) return false;
	if (!deser_u32(&txin->nSequence, buf)) return false;
	return true;
}

void ser_bp_txin(GString *s, const struct bp_txin *txin)
{
	ser_bp_outpt(s, &txin->prevout);
	ser_varstr(s, txin->scriptSig);
	ser_u32(s, txin->nSequence);
}

void bp_txin_free(struct bp_txin *txin)
{
	bp_outpt_free(&txin->prevout);

	if (txin->scriptSig) {
		g_string_free(txin->scriptSig, TRUE);
		txin->scriptSig = NULL;
	}
}

void bp_txout_init(struct bp_txout *txout)
{
	memset(txout, 0, sizeof(*txout));
}

bool deser_bp_txout(struct bp_txout *txout, struct buffer *buf)
{
	if (!deser_s64(&txout->nValue, buf)) return false;
	if (!deser_varstr(&txout->scriptPubKey, buf)) return false;
	return true;
}

void ser_bp_txout(GString *s, const struct bp_txout *txout)
{
	ser_s64(s, txout->nValue);
	ser_varstr(s, txout->scriptPubKey);
}

void bp_txout_free(struct bp_txout *txout)
{
	if (txout->scriptPubKey) {
		g_string_free(txout->scriptPubKey, TRUE);
		txout->scriptPubKey = NULL;
	}
}

