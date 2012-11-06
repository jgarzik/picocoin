#ifndef __LIBCCOIN_BASE58_H__
#define __LIBCCOIN_BASE58_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <glib.h>

extern GString *base58_encode(const void *data_, size_t data_len);
extern GString *base58_address_encode(unsigned char addrtype, const void *data,
			       size_t data_len);
extern GString *base58_decode(const char *s_in);

#endif /* __LIBCCOIN_BASE58_H__ */
