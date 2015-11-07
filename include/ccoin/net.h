#ifndef __LIBCCOIN_NET_H__
#define __LIBCCOIN_NET_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

extern const char ipv4_mapped_pfx[12];

static inline bool is_ipv4_mapped(const unsigned char *ipaddr)
{
	return memcmp(ipaddr, ipv4_mapped_pfx, 12) == 0;
}

extern void bn_group(unsigned char *group, unsigned int *group_len,
			const unsigned char *ipaddr);
extern void bn_address_str(char *host, size_t hostsz, const unsigned char *ipaddr);

#ifdef __cplusplus
}
#endif

#endif /* __LIBCCOIN_NET_H__ */
