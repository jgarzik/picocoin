
#include "picocoin-config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <glib.h>
#include "picocoin.h"

static const char *dns_seeds[] = {
	"seed.bitcoin.sipa.be",
	"dnsseed.bluematt.me",
	"dnsseed.bitcoin.dashjr.org",
	"bitseed.xf2.org",
};

static GList *add_seed_addr(GList *l, const struct addrinfo *ai)
{
	struct p2p_addr *addr;

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

	addr->port = 8333;

	l = g_list_append(l, addr);

	return l;

err_out:
	free(addr);
	return l;
}

static GList *query_seed(GList *l, const char *seedname)
{
	struct addrinfo hints, *res;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(seedname, NULL, &hints, &res))
		return l;

	struct addrinfo *rp;
	for (rp = res; rp != NULL; rp = rp->ai_next)
		l = add_seed_addr(l, rp);

	freeaddrinfo(res);

	return l;
}

GList *get_dns_seed_addrs(void)
{
	unsigned int i;
	GList *l = NULL;

	for (i = 0; i < ARRAY_SIZE(dns_seeds); i++)
		l = query_seed(l, dns_seeds[i]);

	return l;
}
