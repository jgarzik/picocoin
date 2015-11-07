#ifndef __LIBCCOIN_CHECKPOINTS_H__
#define __LIBCCOIN_CHECKPOINTS_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <ccoin/coredefs.h>
#include <ccoin/buint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct bp_checkpoint {
	unsigned int	height;
	const char	*hashstr;
};

struct bp_checkpoint_set {
	enum chains			chain;
	unsigned int			ckpt_len;
	const struct bp_checkpoint	*ckpts;
};

extern const struct bp_checkpoint_set bp_ckpts[];
extern bool bp_ckpt_block(enum chains chain, unsigned int height, const bu256_t *hash);
extern unsigned int bp_ckpt_last(enum chains chain);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_CHECKPOINTS_H__ */
