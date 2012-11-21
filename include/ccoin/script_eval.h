#ifndef __LIBCCOIN_SCRIPT_EVAL_H__
#define __LIBCCOIN_SCRIPT_EVAL_H__

#include <stdbool.h>
#include <glib.h>
#include <ccoin/core.h>

extern bool bp_tx_sighash(bu256_t *hash, GString *scriptCode,
		   const struct bp_tx *txTo, unsigned int nIn,
		   int nHashType);
extern bool bp_script_verify(const GString *scriptSig, const GString *scriptPubKey,
		      const struct bp_tx *txTo, unsigned int nIn,
		      unsigned int flags, int nHashType);
extern bool bp_verify_sig(const struct bp_tx *txFrom, const struct bp_tx *txTo,
		   unsigned int nIn, unsigned int flags, int nHashType);

#endif /* __LIBCCOIN_SCRIPT_EVAL_H__ */
