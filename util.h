#ifndef __PICOCOIN_UTIL_H__
#define __PICOCOIN_UTIL_H__

extern void reverse_copy(unsigned char *dst, const unsigned char *src, size_t len);
extern void Hash(unsigned char *md256, const void *data, size_t data_len);
extern void Hash4(unsigned char *md32, const void *data, size_t data_len);
extern void Hash160(unsigned char *md160, const void *data, size_t data_len);

#endif /* __PICOCOIN_UTIL_H__ */
