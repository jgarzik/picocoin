#ifndef __PICOCOIN_H__
#define __PICOCOIN_H__

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <glib.h>

struct p2p_addr {
	unsigned char	ip[16];
	unsigned short	port;
	uint64_t	nServices;
};

struct buffer {
	void		*p;
	size_t		len;
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

/* dns.c */
extern GList *get_dns_seed_addrs(void);

/* main.c */
extern GHashTable *settings;
extern const char ipv4_mapped_pfx[12];
extern const unsigned char netmagic_main[4];

/* aes.c */
extern GString *read_aes_file(const char *filename, void *key, size_t key_len,
			      size_t max_file_len);
extern bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len);

static inline bool is_ipv4_mapped(const unsigned char *ipaddr)
{
	return memcmp(ipaddr, ipv4_mapped_pfx, 12) == 0;
}

static inline char *setting(const char *key)
{
	return g_hash_table_lookup(settings, key);
}

#endif /* __PICOCOIN_H__ */
