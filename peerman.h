#ifndef __PICOCOIN_PEERMAN_H__
#define __PICOCOIN_PEERMAN_H__

#include <stdbool.h>
#include <glib.h>
#include "core.h"

struct peer_manager {
	GList		*addrlist;	/* of struct bp_address */
	unsigned int	count;		/* # of peers in addrlist */
};

extern void peerman_free(struct peer_manager *peers);
extern struct peer_manager *peerman_read(void);
extern struct peer_manager *peerman_seed(void);
extern bool peerman_write(struct peer_manager *peers);
extern struct bp_address *peerman_pop(struct peer_manager *peers);

#endif /* __PICOCOIN_PEERMAN_H__ */
