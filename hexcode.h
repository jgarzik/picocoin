#ifndef __LIBCCOIN_HEXCODE_H__
#define __LIBCCOIN_HEXCODE_H__

#include <stdbool.h>

extern bool decode_hex(void *p, size_t max_len, const char *hexstr, size_t *out_len_);
extern void encode_hex(char *hexstr, const void *p_, size_t len);

#endif /* __LIBCCOIN_HEXCODE_H__ */
