#ifndef __PICOCOIN_WALLET_H__
#define __PICOCOIN_WALLET_H__

struct wallet {
	GArray	*keys;
};

extern struct wallet *load_wallet(void);
extern bool store_wallet(struct wallet *);
extern void wallet_free(struct wallet *);
extern void wallet_new_address(void);

#endif /* __PICOCOIN_WALLET_H__ */
