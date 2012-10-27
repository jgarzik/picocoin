#ifndef __PICOCOIN_BASE58_H__
#define __PICOCOIN_BASE58_H__

extern GString *base58_encode(const void *data_, size_t data_len);
extern GString *base58_address_encode(unsigned char addrtype, const void *data,
			       size_t data_len);

#endif /* __PICOCOIN_BASE58_H__ */
