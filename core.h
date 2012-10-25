#ifndef __PICOCOIN_CORE_H__
#define __PICOCOIN_CORE_H__

#include <openssl/bn.h>
#include <stdint.h>

struct bp_address {
	uint32_t	nTime;
	uint64_t	nServices;
	unsigned char	ip[16];
	uint16_t	port;
};

extern bool deser_bp_addr(unsigned int protover,
		struct bp_address *addr, struct buffer *buf);
extern void ser_bp_addr(GString *s, unsigned int protover, const struct bp_address *addr);
static inline void bp_addr_free(struct bp_address *addr) {}

struct bp_inv {
	uint32_t	type;
	BIGNUM		hash;
};

extern void bp_inv_init(struct bp_inv *inv);
extern bool deser_bp_inv(struct bp_inv *inv, struct buffer *buf);
extern void ser_bp_inv(GString *s, const struct bp_inv *inv);
extern void bp_inv_free(struct bp_inv *inv);

struct bp_locator {
	uint32_t	nVersion;
	GPtrArray	*vHave;
};

extern void bp_locator_init(struct bp_locator *locator);
extern bool deser_bp_locator(struct bp_locator *locator, struct buffer *buf);
extern void ser_bp_locator(GString *s, const struct bp_locator *locator);
extern void bp_locator_free(struct bp_locator *locator);

struct bp_outpt {
	BIGNUM		hash;
	uint32_t	n;
};

extern void bp_outpt_init(struct bp_outpt *outpt);
extern bool deser_bp_outpt(struct bp_outpt *outpt, struct buffer *buf);
extern void ser_bp_outpt(GString *s, const struct bp_outpt *outpt);
extern void bp_outpt_free(struct bp_outpt *outpt);

static inline bool bp_outpt_null(const struct bp_outpt *outpt)
{
	return BN_is_zero(&outpt->hash) && outpt->n == 0xffffffff;
}

struct bp_txin {
	struct bp_outpt	prevout;
	GString		*scriptSig;
	uint32_t	nSequence;
};

extern void bp_txin_init(struct bp_txin *txin);
extern bool deser_bp_txin(struct bp_txin *txin, struct buffer *buf);
extern void ser_bp_txin(GString *s, const struct bp_txin *txin);
extern void bp_txin_free(struct bp_txin *txin);
static inline bool bp_txin_valid(const struct bp_txin *txin) { return true; }

struct bp_txout {
	int64_t		nValue;
	GString		*scriptPubKey;
};

extern void bp_txout_init(struct bp_txout *txout);
extern bool deser_bp_txout(struct bp_txout *txout, struct buffer *buf);
extern void ser_bp_txout(GString *s, const struct bp_txout *txout);
extern void bp_txout_free(struct bp_txout *txout);
static inline bool bp_txout_valid(const struct bp_txout *txout)
{
	if (txout->nValue < 0 || txout->nValue > 21000000ULL * 100000000ULL)
		return false;
	return true;
}

struct bp_tx {
	uint32_t	nVersion;
	GPtrArray	*vin;
	GPtrArray	*vout;
	uint32_t	nLockTime;
};

extern void bp_tx_init(struct bp_tx *tx);
extern bool deser_bp_tx(struct bp_tx *tx, struct buffer *buf);
extern void ser_bp_tx(GString *s, const struct bp_tx *tx);
extern void bp_tx_free(struct bp_tx *tx);
extern bool bp_tx_valid(const struct bp_tx *tx);

static inline bool bp_tx_coinbase(const struct bp_tx *tx)
{
	if (!tx->vin || tx->vin->len != 1)
		return false;

	struct bp_txin *txin = g_ptr_array_index(tx->vin, 0);
	if (!bp_outpt_null(&txin->prevout))
		return false;
	
	return true;
}

struct bp_block {
	uint32_t	nVersion;
	BIGNUM		hashPrevBlock;
	BIGNUM		hashMerkleRoot;
	uint32_t	nTime;
	uint32_t	nBits;
	uint32_t	nNonce;
	GPtrArray	*vtx;
};

extern void bp_block_init(struct bp_block *block);
extern bool deser_bp_block(struct bp_block *block, struct buffer *buf);
extern void ser_bp_block(GString *s, const struct bp_block *block);
extern void bp_block_free(struct bp_block *block);

#endif /* __PICOCOIN_CORE_H__ */
