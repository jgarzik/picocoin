#ifndef __PICOCOIN_WALLET_H__
#define __PICOCOIN_WALLET_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

extern void cur_wallet_new_address(void);
extern void cur_wallet_create(void);
extern void cur_wallet_info(void);
extern void cur_wallet_dump(void);
extern void cur_wallet_addresses(void);
extern void cur_wallet_free(void);

#endif /* __PICOCOIN_WALLET_H__ */
