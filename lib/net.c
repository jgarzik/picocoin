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
#include <string.h>
#include <ccoin/net.h>

static const unsigned char pchOnionCat[] = {0xFD,0x87,0xD8,0x7E,0xEB,0x43};
const char ipv4_mapped_pfx[12] = "\0\0\0\0\0\0\0\0\0\0\xff\xff";

enum networktype {
	NET_UNROUTABLE,
	NET_IPV4,
	NET_IPV6,
	NET_TOR,
};

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

#define GB(n) (15 - (n))

static bool is_RFC1918(const unsigned char *ipaddr)
{
	return is_ipv4_mapped(ipaddr) &&
		(ipaddr[GB(3)] == 10 ||
		(ipaddr[GB(3)] == 192 && ipaddr[GB(2)] == 168) ||
		(ipaddr[GB(3)] == 172 && (ipaddr[GB(2)] >= 16 && ipaddr[GB(2)] <= 31)));
}

static bool is_RFC3849(const unsigned char *ipaddr)
{
	return	ipaddr[GB(15)] == 0x20 &&
		ipaddr[GB(14)] == 0x01 &&
		ipaddr[GB(13)] == 0x0d &&
		ipaddr[GB(12)] == 0xb8;
}

static bool is_RFC3927(const unsigned char *ipaddr)
{
	return	is_ipv4_mapped(ipaddr) &&
		ipaddr[GB(3)] == 169 &&
		ipaddr[GB(2)] == 254;
}

static bool is_RFC3964(const unsigned char *ipaddr)
{
	return	ipaddr[GB(15)] == 0x20 &&
		ipaddr[GB(14)] == 0x02;
}

static bool is_RFC4193(const unsigned char *ipaddr)
{
	return ((ipaddr[GB(15)] & 0xfe) == 0xfc);
}

static bool is_RFC4380(const unsigned char *ipaddr)
{
	return	ipaddr[GB(15)] == 0x20 &&
		ipaddr[GB(14)] == 0x01 &&
		ipaddr[GB(13)] == 0x00 &&
		ipaddr[GB(12)] == 0x00;
}

static bool is_RFC4843(const unsigned char *ipaddr)
{
	return	ipaddr[GB(15)] == 0x20 &&
		ipaddr[GB(14)] == 0x01 &&
		ipaddr[GB(13)] == 0x00 &&
		((ipaddr[GB(12)] & 0xf0) == 0x10);
}

static bool is_RFC4862(const unsigned char *ipaddr)
{
	static const unsigned char pchRFC4862[] = {0xFE,0x80,0,0,0,0,0,0};
	return (memcmp(ipaddr, pchRFC4862, sizeof(pchRFC4862)) == 0);
}

static bool is_RFC6052(const unsigned char *ipaddr)
{
	static const unsigned char pchRFC6052[] = {0,0x64,0xFF,0x9B,0,0,0,0,0,0,0,0};
	return (memcmp(ipaddr, pchRFC6052, sizeof(pchRFC6052)) == 0);
}

static bool is_RFC6145(const unsigned char *ipaddr)
{
	static const unsigned char pchRFC6145[] = {0,0,0,0,0,0,0,0,0xFF,0xFF,0,0};
	return (memcmp(ipaddr, pchRFC6145, sizeof(pchRFC6145)) == 0);
}

static bool is_local(const unsigned char *ipaddr)
{
	if (is_ipv4_mapped(ipaddr) &&
	    (ipaddr[GB(3)] == 127 || ipaddr[GB(3)] == 0))
		return true;

	static const unsigned char pchLocal[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
	if (!memcmp(ipaddr, pchLocal, sizeof(pchLocal)))
		return true;

	return false;
}

static bool is_valid(const unsigned char *ipaddr)
{
	static const unsigned char none[16] = {};
	if (!memcmp(ipaddr, none, 16))
		return false;

	if (is_RFC3849(ipaddr))
		return false;

	if (is_ipv4_mapped(ipaddr) &&
	    !memcmp(ipaddr + 12, none, 4))
		return false;

	return true;
}

static bool is_tor(const unsigned char *ipaddr)
{
	return (memcmp(ipaddr, pchOnionCat, sizeof(pchOnionCat)) == 0);
}

static bool is_routable(const unsigned char *ipaddr)
{
	return is_valid(ipaddr) &&
		!(	is_RFC1918(ipaddr) ||
			is_RFC3927(ipaddr) ||
			is_RFC4862(ipaddr) ||
			(is_RFC4193(ipaddr) && !is_tor(ipaddr)) ||
			is_RFC4843(ipaddr) ||
			is_local(ipaddr)
		);
}

#define PUSH_BACK(ch) {				\
	unsigned int tmplen = *group_len;	\
	group[tmplen] = (unsigned char)(ch);	\
	*group_len = tmplen + 1;		\
	}

void bn_group(unsigned char *group, unsigned int *group_len,
	      const unsigned char *ipaddr)
{
	*group_len = 0;
	unsigned char class = NET_IPV6;
	unsigned int ofs = 0;
	unsigned int bits = 16;

	if (is_local(ipaddr)) {
		class = 255;
		bits = 0;
	}

	if (!is_routable(ipaddr)) {
		class = NET_UNROUTABLE;
		bits = 0;
	}

	else if (is_ipv4_mapped(ipaddr) ||
		 is_RFC6052(ipaddr) || is_RFC6145(ipaddr)) {
		class = NET_IPV4;
		ofs = 12;
	}

	else if (is_RFC3964(ipaddr)) {
		class = NET_IPV4;
		ofs = 2;
	}

	else if (is_RFC4380(ipaddr)) {
		PUSH_BACK(NET_IPV4);
		PUSH_BACK(ipaddr[GB(3)] ^ 0xFF);
		PUSH_BACK(ipaddr[GB(2)] ^ 0xFF);
		return;
	}
	else if (is_tor(ipaddr)) {
		class = NET_TOR;
		ofs = 6;
		bits = 4;
	}

	else if (ipaddr[GB(15)] == 0x20 && ipaddr[GB(14)] == 0x11 &&
		 ipaddr[GB(13)] == 0x04 && ipaddr[GB(12)] == 0x70)
		bits = 36;

	else
		bits = 32;

	PUSH_BACK(class);
	while (bits >= 8) {
		PUSH_BACK(ipaddr[GB(15 - ofs)]);
		ofs++;
		bits -= 8;
	}
	if (bits > 0)
		PUSH_BACK(ipaddr[GB(15 - ofs)] | ((1 << bits) - 1));
}

