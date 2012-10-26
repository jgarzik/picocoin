#ifndef __PICOCOIN_WALLET_H__
#define __PICOCOIN_WALLET_H__

struct wallet {
	uint32_t	version;
	GPtrArray	*keys;
};

extern struct wallet *load_wallet(void);
extern bool store_wallet(struct wallet *);
extern void wallet_free(struct wallet *);
extern void wallet_new_address(void);
extern void wallet_create(void);
extern void wallet_addresses(void);
extern void cur_wallet_free(void);

#endif /* __PICOCOIN_WALLET_H__ */
