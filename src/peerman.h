#ifndef __PICOCOIN_PEERMAN_H__
#define __PICOCOIN_PEERMAN_H__
/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdbool.h>
#include <glib.h>
#include <ccoin/core.h>

struct peer_manager {
	GHashTable	*map_addr;
	GList		*addrlist;	/* of struct bp_address */
};

extern void peerman_free(struct peer_manager *peers);
extern struct peer_manager *peerman_read(void);
extern struct peer_manager *peerman_seed(bool use_dns);
extern bool peerman_write(struct peer_manager *peers);
extern struct bp_address *peerman_pop(struct peer_manager *peers);
extern void peerman_add(struct peer_manager *peers,
		 const struct bp_address *addr_in, bool known_working);
extern void peerman_addstr(struct peer_manager *peers, const char *addr_str);

#endif /* __PICOCOIN_PEERMAN_H__ */
