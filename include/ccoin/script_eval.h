#ifndef __LIBCCOIN_SCRIPT_EVAL_H__
#define __LIBCCOIN_SCRIPT_EVAL_H__

#include <stdbool.h>
#include <glib.h>
#include <ccoin/core.h>

extern bool bp_tx_sighash(bu256_t *hash, GString *scriptCode,
		   const struct bp_tx *txTo, unsigned int nIn,
		   int nHashType);

#endif /* __LIBCCOIN_SCRIPT_EVAL_H__ */
