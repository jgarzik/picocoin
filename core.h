#ifndef __PICOCOIN_CORE_H__
#define __PICOCOIN_CORE_H__

#include <openssl/bn.h>
#include <stdint.h>

struct bp_address {
	uint32_t	nTime;
	uint64_t	nServices;
	unsigned char	ip[16];
	uint16_t	port;
};

extern bool deser_bp_addr(unsigned int protover,
		struct bp_address *addr, struct buffer *buf);
extern void ser_bp_addr(GString *s, unsigned int protover, const struct bp_address *addr);
static inline void bp_addr_free(struct bp_address *addr) {}

struct bp_outpt {
	BIGNUM		hash;
	uint32_t	n;
};

extern void bp_outpt_init(struct bp_outpt *outpt);
extern bool deser_bp_outpt(struct bp_outpt *outpt, struct buffer *buf);
extern void ser_bp_outpt(GString *s, const struct bp_outpt *outpt);
extern void bp_outpt_free(struct bp_outpt *outpt);

#endif /* __PICOCOIN_CORE_H__ */
