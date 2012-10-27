#ifndef __LIBCCOIN_ADDRESS_H__
#define __LIBCCOIN_ADDRESS_H__

#include <glib.h>
#include "key.h"

extern GString *bp_pubkey_get_address(struct bp_key *key, unsigned char addrtype);

#endif /* __LIBCCOIN_ADDRESS_H__ */
