#ifndef __LIBCCOIN_ADDRESS_H__
#define __LIBCCOIN_ADDRESS_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <glib.h>
#include <ccoin/key.h>

extern GString *bp_pubkey_get_address(struct bp_key *key, unsigned char addrtype);

#endif /* __LIBCCOIN_ADDRESS_H__ */
