/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <sys/types.h>
#ifdef WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ccoin/util.h>
#include <ccoin/core.h>
#include <ccoin/clist.h>

static const char *dns_seeds[] = {
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"seed.bitcoinstats.com",
	"bitseed.xf2.org",
};

static clist *add_seed_addr(clist *l, const struct addrinfo *ai,
			    unsigned int def_port)
{
	struct bp_address *addr;

	addr = calloc(1, sizeof(*addr));
	if (!addr)
		return l;

	if (ai->ai_family == AF_INET6) {
		struct sockaddr_in6 *saddr = (struct sockaddr_in6 *)ai->ai_addr;
		memcpy(&addr->ip, &saddr->sin6_addr, 16);
	} else if (ai->ai_family == AF_INET) {
		struct sockaddr_in *saddr = (struct sockaddr_in *)ai->ai_addr;
		memset(&addr->ip[0], 0, 10);
		memset(&addr->ip[10], 0xff, 2);
		memcpy(&addr->ip[12], &saddr->sin_addr, 4);
	} else
		goto err_out;

	addr->nTime = (uint32_t) (time(NULL) - (24 * 60 * 60));
	addr->port = def_port;
	addr->nServices = NODE_NETWORK;

	l = clist_append(l, addr);

	return l;

err_out:
	free(addr);
	return l;
}

clist *bu_dns_lookup(clist *l, const char *seedname, unsigned int def_port)
{
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(seedname, NULL, &hints, &res))
		return l;

	struct addrinfo *rp;
	for (rp = res; rp != NULL; rp = rp->ai_next)
		l = add_seed_addr(l, rp, def_port);

	freeaddrinfo(res);

	return l;
}

clist *bu_dns_seed_addrs(void)
{
	unsigned int i;
	clist *l = NULL;

	for (i = 0; i < ARRAY_SIZE(dns_seeds); i++)
		l = bu_dns_lookup(l, dns_seeds[i], 8333);

	return l;
}
