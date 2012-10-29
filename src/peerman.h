#ifndef __PICOCOIN_PEERMAN_H__
#define __PICOCOIN_PEERMAN_H__

#include <stdbool.h>
#include <glib.h>
#include <ccoin/core.h>

struct peer_manager {
	GHashTable	*map_addr;
	GList		*addrlist;	/* of struct bp_address */
};

extern void peerman_free(struct peer_manager *peers);
extern struct peer_manager *peerman_read(void);
extern struct peer_manager *peerman_seed(void);
extern bool peerman_write(struct peer_manager *peers);
extern struct bp_address *peerman_pop(struct peer_manager *peers);
extern void peerman_add(struct peer_manager *peers,
		 const struct bp_address *addr_in, bool known_working);

#endif /* __PICOCOIN_PEERMAN_H__ */
