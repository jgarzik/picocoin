#ifndef __PICOCOIN_WALLET_H__
#define __PICOCOIN_WALLET_H__

#include <stdint.h>
#include <stdbool.h>
#include <glib.h>

struct wallet {
	uint32_t	version;
	unsigned char	netmagic[4];

	GPtrArray	*keys;
};

extern struct wallet *load_wallet(void);
extern bool store_wallet(struct wallet *);
extern void wallet_free(struct wallet *);
extern void wallet_new_address(void);
extern void wallet_create(void);
extern void wallet_info(void);
extern void wallet_addresses(void);
extern void cur_wallet_free(void);

#endif /* __PICOCOIN_WALLET_H__ */
