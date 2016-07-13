#ifndef __LIBCCOIN_NET_DNS_H__
#define __LIBCCOIN_NET_DNS_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/clist.h>                // for clist, clist_append

#ifdef __cplusplus
extern "C" {
#endif

extern clist *bu_dns_lookup(clist *l, const char *seedname, unsigned int def_port);
extern clist *bu_dns_seed_addrs(void);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_NET_DNS_H__ */
