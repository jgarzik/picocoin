#ifndef __LIBCCOIN_SCRIPT_H__
#define __LIBCCOIN_SCRIPT_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <ccoin/buffer.h>
#include <ccoin/core.h>
#include <ccoin/clist.h>
#include <ccoin/buint.h>
#include <ccoin/key.h>
#include <ccoin/parr.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Signature hash types/flags */
enum
{
	SIGHASH_ALL = 1,
	SIGHASH_NONE = 2,
	SIGHASH_SINGLE = 3,
	SIGHASH_ANYONECANPAY = 0x80,
};

/** Script verification flags */
enum
{
    SCRIPT_VERIFY_NONE      = 0,
    SCRIPT_VERIFY_P2SH      = (1U << 0),
    SCRIPT_VERIFY_STRICTENC = (1U << 1),
};

enum txnouttype
{
	TX_NONSTANDARD,
	// 'standard' transaction types:
	TX_PUBKEY,
	TX_PUBKEYHASH,
	TX_SCRIPTHASH,
	TX_MULTISIG,
};

/** Script opcodes */
enum opcodetype
{
	// push value
	OP_0 = 0x00,
	OP_FALSE = OP_0,
	OP_PUSHDATA1 = 0x4c,
	OP_PUSHDATA2 = 0x4d,
	OP_PUSHDATA4 = 0x4e,
	OP_1NEGATE = 0x4f,
	OP_RESERVED = 0x50,
	OP_1 = 0x51,
	OP_TRUE=OP_1,
	OP_2 = 0x52,
	OP_3 = 0x53,
	OP_4 = 0x54,
	OP_5 = 0x55,
	OP_6 = 0x56,
	OP_7 = 0x57,
	OP_8 = 0x58,
	OP_9 = 0x59,
	OP_10 = 0x5a,
	OP_11 = 0x5b,
	OP_12 = 0x5c,
	OP_13 = 0x5d,
	OP_14 = 0x5e,
	OP_15 = 0x5f,
	OP_16 = 0x60,

	// control
	OP_NOP = 0x61,
	OP_VER = 0x62,
	OP_IF = 0x63,
	OP_NOTIF = 0x64,
	OP_VERIF = 0x65,
	OP_VERNOTIF = 0x66,
	OP_ELSE = 0x67,
	OP_ENDIF = 0x68,
	OP_VERIFY = 0x69,
	OP_RETURN = 0x6a,

	// stack ops
	OP_TOALTSTACK = 0x6b,
	OP_FROMALTSTACK = 0x6c,
	OP_2DROP = 0x6d,
	OP_2DUP = 0x6e,
	OP_3DUP = 0x6f,
	OP_2OVER = 0x70,
	OP_2ROT = 0x71,
	OP_2SWAP = 0x72,
	OP_IFDUP = 0x73,
	OP_DEPTH = 0x74,
	OP_DROP = 0x75,
	OP_DUP = 0x76,
	OP_NIP = 0x77,
	OP_OVER = 0x78,
	OP_PICK = 0x79,
	OP_ROLL = 0x7a,
	OP_ROT = 0x7b,
	OP_SWAP = 0x7c,
	OP_TUCK = 0x7d,

	// splice ops
	OP_CAT = 0x7e,
	OP_SUBSTR = 0x7f,
	OP_LEFT = 0x80,
	OP_RIGHT = 0x81,
	OP_SIZE = 0x82,

	// bit logic
	OP_INVERT = 0x83,
	OP_AND = 0x84,
	OP_OR = 0x85,
	OP_XOR = 0x86,
	OP_EQUAL = 0x87,
	OP_EQUALVERIFY = 0x88,
	OP_RESERVED1 = 0x89,
	OP_RESERVED2 = 0x8a,

	// numeric
	OP_1ADD = 0x8b,
	OP_1SUB = 0x8c,
	OP_2MUL = 0x8d,
	OP_2DIV = 0x8e,
	OP_NEGATE = 0x8f,
	OP_ABS = 0x90,
	OP_NOT = 0x91,
	OP_0NOTEQUAL = 0x92,

	OP_ADD = 0x93,
	OP_SUB = 0x94,
	OP_MUL = 0x95,
	OP_DIV = 0x96,
	OP_MOD = 0x97,
	OP_LSHIFT = 0x98,
	OP_RSHIFT = 0x99,

	OP_BOOLAND = 0x9a,
	OP_BOOLOR = 0x9b,
	OP_NUMEQUAL = 0x9c,
	OP_NUMEQUALVERIFY = 0x9d,
	OP_NUMNOTEQUAL = 0x9e,
	OP_LESSTHAN = 0x9f,
	OP_GREATERTHAN = 0xa0,
	OP_LESSTHANOREQUAL = 0xa1,
	OP_GREATERTHANOREQUAL = 0xa2,
	OP_MIN = 0xa3,
	OP_MAX = 0xa4,

	OP_WITHIN = 0xa5,

	// crypto
	OP_RIPEMD160 = 0xa6,
	OP_SHA1 = 0xa7,
	OP_SHA256 = 0xa8,
	OP_HASH160 = 0xa9,
	OP_HASH256 = 0xaa,
	OP_CODESEPARATOR = 0xab,
	OP_CHECKSIG = 0xac,
	OP_CHECKSIGVERIFY = 0xad,
	OP_CHECKMULTISIG = 0xae,
	OP_CHECKMULTISIGVERIFY = 0xaf,

	// expansion
	OP_NOP1 = 0xb0,
	OP_NOP2 = 0xb1,
	OP_NOP3 = 0xb2,
	OP_NOP4 = 0xb3,
	OP_NOP5 = 0xb4,
	OP_NOP6 = 0xb5,
	OP_NOP7 = 0xb6,
	OP_NOP8 = 0xb7,
	OP_NOP9 = 0xb8,
	OP_NOP10 = 0xb9,



	// template matching params
	OP_SMALLINTEGER = 0xfa,
	OP_PUBKEYS = 0xfb,
	OP_PUBKEYHASH = 0xfd,
	OP_PUBKEY = 0xfe,

	OP_INVALIDOPCODE = 0xff,
};

struct bscript_parser {
	struct const_buffer	*buf;		/* current parse offset */

	bool			error;		/* parse error in stream? */
};

struct bscript_op {
	enum opcodetype		op;		/* opcode found */
	struct const_buffer	data;		/* associated data, if any */
};

struct bscript_addr {
	enum txnouttype		txtype;
	clist			*pub;		/* of struct buffer */
	clist			*pubhash;	/* of struct buffer */
};

extern const char *GetOpName(enum opcodetype opcode);
extern enum opcodetype GetOpType(const char *opname);

/*
 * script parsing
 */

extern bool bsp_getop(struct bscript_op *op, struct bscript_parser *bp);
extern parr *bsp_parse_all(const void *data_, size_t data_len);
extern enum txnouttype bsp_classify(parr *ops);
extern bool bsp_addr_parse(struct bscript_addr *addr,
		    const void *data, size_t data_len);
extern void bsp_addr_free(struct bscript_addr *addr);
extern bool is_bsp_pushonly(struct const_buffer *buf);
extern bool is_bsp_pubkey(parr *ops);
extern bool is_bsp_pubkeyhash(parr *ops);
extern bool is_bsp_scripthash(parr *ops);
extern bool is_bsp_multisig(parr *ops);

static inline bool is_bsp_pushdata(enum opcodetype op)
{
	return (op <= OP_PUSHDATA4);
}

static inline bool is_bsp_p2sh(struct const_buffer *buf)
{
	const unsigned char *vch = (const unsigned char *)(buf->p);
	return	(buf->len == 23 &&
		 vch[0] == OP_HASH160 &&
		 vch[1] == 0x14 &&
		 vch[22] == OP_EQUAL);
}

static inline bool is_bsp_p2sh_str(const cstring *s)
{
	struct const_buffer buf = { s->str, s->len };
	return is_bsp_p2sh(&buf);
}

static inline void bsp_start(struct bscript_parser *bp,
			     struct const_buffer *buf)
{
	bp->buf = buf;
	bp->error = false;
}

/*
 * script validation and signing
 */

extern void bp_tx_sighash(bu256_t *hash, const cstring *scriptCode,
		   const struct bp_tx *txTo, unsigned int nIn,
		   int nHashType);
extern bool bp_script_verify(const cstring *scriptSig, const cstring *scriptPubKey,
		      const struct bp_tx *txTo, unsigned int nIn,
		      unsigned int flags, int nHashType);
extern bool bp_verify_sig(const struct bp_utxo *txFrom, const struct bp_tx *txTo,
		   unsigned int nIn, unsigned int flags, int nHashType);

extern bool bp_script_sign(struct bp_keystore *ks, const cstring *fromPubKey,
		    const struct bp_tx *txTo, unsigned int nIn,
		    int nHashType);
extern bool bp_sign_sig(struct bp_keystore *ks, const struct bp_utxo *txFrom,
		 struct bp_tx *txTo, unsigned int nIn,
		 unsigned int flags, int nHashType);

/*
 * script building
 */

extern cstring *bsp_make_pubkeyhash(cstring *hash);
extern cstring *bsp_make_scripthash(cstring *hash);
extern void bsp_push_data(cstring *s, const void *data, size_t data_len);
extern void bsp_push_int64(cstring *s, int64_t v);
extern void bsp_push_uint64(cstring *s, uint64_t v);

static inline void bsp_push_op(cstring *s, enum opcodetype op)
{
	uint8_t c = (uint8_t) op;

	cstr_append_buf(s, &c, sizeof(c));
}

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_SCRIPT_H__ */
