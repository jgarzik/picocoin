
#include "picocoin-config.h"

#include "picocoin.h"
#include "core.h"
#include "coredefs.h"
#include "serialize.h"

bool deser_addr(unsigned int protover,
		struct bp_address *addr, struct buffer *buf)
{
	if (protover >= CADDR_TIME_VERSION)
		if (!deser_u32(&addr->nTime, buf)) return false;
	if (!deser_u64(&addr->nServices, buf)) return false;
	if (!deser_bytes(&addr->ip, buf, 16)) return false;
	if (!deser_u16(&addr->port, buf)) return false;
	return true;
}

GString *ser_addr(unsigned int protover, const struct bp_address *addr)
{
	GString *s = g_string_sized_new(4 + 8 + 16 + 2);

	if (protover >= CADDR_TIME_VERSION) 
		ser_u32(s, addr->nTime);
	ser_u64(s, addr->nServices);
	ser_bytes(s, addr->ip, 16);
	ser_u16(s, addr->port);

	return s;
}
