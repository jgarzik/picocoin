#ifndef __PICOCOIN_CORE_H__
#define __PICOCOIN_CORE_H__

#include <stdint.h>

struct bp_address {
	uint32_t	nTime;
	uint64_t	nServices;
	unsigned char	ip[16];
	uint16_t	port;
};

extern bool deser_addr(unsigned int protover,
		struct bp_address *addr, struct buffer *buf);
extern GString *ser_addr(unsigned int protover, const struct bp_address *addr);

#endif /* __PICOCOIN_CORE_H__ */
