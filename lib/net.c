/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#include <ccoin/net.h>

const char ipv4_mapped_pfx[12] = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

void bn_address_str(char *host, size_t hostsz, const unsigned char *ipaddr)
{
	bool is_ipv4 = is_ipv4_mapped(ipaddr);

	if (is_ipv4) {
		struct sockaddr_in saddr;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin_family = AF_INET;
		memcpy(&saddr.sin_addr, &ipaddr[12], 4);

		getnameinfo((struct sockaddr *) &saddr, sizeof(saddr),
			    host, hostsz,
			    NULL, 0, NI_NUMERICHOST);
	} else {
		struct sockaddr_in6 saddr;

		memset(&saddr, 0, sizeof(saddr));
		saddr.sin6_family = AF_INET6;
		memcpy(&saddr.sin6_addr, ipaddr, 16);

		getnameinfo((struct sockaddr *) &saddr, sizeof(saddr),
			    host, hostsz,
			    NULL, 0, NI_NUMERICHOST);
	}

	host[hostsz - 1] = 0;
}

