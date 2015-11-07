#ifndef __LIBCCOIN_ADDRESS_H__
#define __LIBCCOIN_ADDRESS_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/key.h>
#include <ccoin/cstr.h>

#ifdef __cplusplus
extern "C" {
#endif

extern cstring *bp_pubkey_get_address(struct bp_key *key, unsigned char addrtype);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_ADDRESS_H__ */
