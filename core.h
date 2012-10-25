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

struct bp_outpt {
	BIGNUM		hash;
	uint32_t	n;
};

extern void bp_outpt_init(struct bp_outpt *outpt);
extern bool deser_bp_outpt(struct bp_outpt *outpt, struct buffer *buf);
extern void ser_bp_outpt(GString *s, const struct bp_outpt *outpt);
extern void bp_outpt_free(struct bp_outpt *outpt);

struct bp_txin {
	struct bp_outpt	prevout;
	GString		*scriptSig;
	uint32_t	nSequence;
};

extern void bp_txin_init(struct bp_txin *txin);
extern bool deser_bp_txin(struct bp_txin *txin, struct buffer *buf);
extern void ser_bp_txin(GString *s, const struct bp_txin *txin);
extern void bp_txin_free(struct bp_txin *txin);

struct bp_txout {
	int64_t		nValue;
	GString		*scriptPubKey;
};

extern void bp_txout_init(struct bp_txout *txout);
extern bool deser_bp_txout(struct bp_txout *txout, struct buffer *buf);
extern void ser_bp_txout(GString *s, const struct bp_txout *txout);
extern void bp_txout_free(struct bp_txout *txout);

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
