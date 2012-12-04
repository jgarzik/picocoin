/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <string.h>
#include "peerman.h"
#include <ccoin/mbr.h>
#include <ccoin/util.h>
#include <ccoin/coredefs.h>
#include <ccoin/compat.h>
#include "picocoin.h"

static guint addr_hash(gconstpointer key)
{
	return djb2_hash(0x1721, key, 16);
}

static gboolean addr_equal(gconstpointer a, gconstpointer b)
{
	return memcmp(a, b, 16) == 0 ? TRUE : FALSE;
}

static struct peer_manager *peerman_new(void)
{
	struct peer_manager *peers;

	peers = calloc(1, sizeof(*peers));
	if (!peers)
		return NULL;
	
	peers->map_addr = g_hash_table_new(addr_hash, addr_equal);

	return peers;
}

void peerman_free(struct peer_manager *peers)
{
	if (!peers)
		return;

	if (peers->map_addr)
		g_hash_table_unref(peers->map_addr);

	g_list_free_full(peers->addrlist, g_free);

	memset(peers, 0, sizeof(*peers));
	free(peers);
}

static void __peerman_add(struct peer_manager *peers, struct bp_address *addr,
			  bool prepend_front)
{
	if (prepend_front)
		peers->addrlist = g_list_prepend(peers->addrlist, addr);
	else
		peers->addrlist = g_list_append(peers->addrlist, addr);

	/* when using GHashTable as a set, key=value enables some
	 * unspecified GLib optimizations
	 */
	g_hash_table_insert(peers->map_addr, addr->ip, addr->ip);
}

static bool peerman_has_addr(struct peer_manager *peers,const unsigned char *ip)
{
	return g_hash_table_lookup_extended(peers->map_addr, ip, NULL, NULL);
}

static bool peerman_read_rec(struct peer_manager *peers,
			     const struct p2p_message *msg)
{
	if (!strncmp(msg->hdr.command, "magic.peers",
		     sizeof(msg->hdr.command)))
		return true;

	if (strncmp(msg->hdr.command, "CAddress", sizeof(msg->hdr.command)) ||
	    (msg->hdr.data_len != sizeof(struct bp_address)))
		return false;

	struct const_buffer buf = { msg->data, msg->hdr.data_len };
	struct bp_address *addr;

	addr = calloc(1, sizeof(*addr));

	if (deser_bp_addr(CADDR_TIME_VERSION, addr, &buf) &&
	    !peerman_has_addr(peers, addr->ip))
		__peerman_add(peers, addr, false);
	else
		free(addr);

	return true;
}

struct peer_manager *peerman_read(void)
{
	char *filename = setting("peers");
	if (!filename)
		return NULL;

	struct peer_manager *peers;

	peers = peerman_new();
	if (!peers)
		return NULL;

	int fd = file_seq_open(filename);
	if (fd < 0) {
		perror(filename);
		goto err_out;
	}

	struct p2p_message msg = {};
	bool read_ok = true;

	while (fread_message(fd, &msg, &read_ok)) {
		if (!peerman_read_rec(peers, &msg))
			goto err_out;
	}

	if (!read_ok)
		goto err_out;

	free(msg.data);
	close(fd);

	return peers;

err_out:
	peerman_free(peers);
	return NULL;
}

struct peer_manager *peerman_seed(void)
{
	struct peer_manager *peers;

	peers = peerman_new();
	if (!peers)
		return NULL;

	/* make DNS query for seed data */
	GList *tmp, *seedlist = bu_dns_seed_addrs();

	if (debugging)
		fprintf(stderr, "peerman: DNS returned %u addresses\n",
			g_list_length(seedlist));

	/* import seed data into peerman */
	tmp = seedlist;
	while (tmp) {
		__peerman_add(peers, tmp->data, true);
		tmp = tmp->next;
	}
	g_list_free(seedlist);

	return peers;
}

static bool ser_peerman(struct peer_manager *peers, int fd)
{
	/* write "magic number" (constant first file record) */
	GString *rec = message_str(chain->netmagic, "magic.peers", NULL, 0);
	unsigned int rec_len = rec->len;
	ssize_t wrc = write(fd, rec->str, rec_len);

	g_string_free(rec, TRUE);

	if (wrc != rec_len)
		return false;

	if (debugging)
		fprintf(stderr, "peerman: %u peers to write\n",
			g_list_length(peers->addrlist));

	/* write peer list */
	GList *tmp = peers->addrlist;
	while (tmp) {
		struct bp_address *addr;

		addr = tmp->data;
		tmp = tmp->next;

		GString *msg_data = g_string_sized_new(sizeof(struct bp_address));
		ser_bp_addr(msg_data, CADDR_TIME_VERSION, addr);

		rec = message_str(chain->netmagic, "CAddress",
				  msg_data->str, msg_data->len);

		rec_len = rec->len;
		wrc = write(fd, rec->str, rec_len);

		g_string_free(rec, TRUE);
		g_string_free(msg_data, TRUE);

		if (wrc != rec_len)
			return false;
	}

	return true;
}

bool peerman_write(struct peer_manager *peers)
{
	char *filename = setting("peers");
	if (!filename)
		return false;

	char tmpfn[strlen(filename) + 32];
	strcpy(tmpfn, filename);
	strcat(tmpfn, ".XXXXXX");

	int fd = mkstemp(tmpfn);
	if (fd < 0)
		return false;

	if (!ser_peerman(peers, fd))
		goto err_out;

	close(fd);
	fd = -1;

	if (rename(tmpfn, filename)) {
		strcat(tmpfn, " rename");
		perror(tmpfn);
		goto err_out;
	}

	return true;

err_out:
	if (fd >= 0)
		close(fd);
	unlink(tmpfn);
	return false;
}

struct bp_address *peerman_pop(struct peer_manager *peers)
{
	struct bp_address *addr;
	GList *tmp;

	tmp = peers->addrlist;
	if (!tmp)
		return NULL;

	addr = tmp->data;

	peers->addrlist = g_list_delete_link(tmp, tmp);

	g_hash_table_remove(peers->map_addr, addr->ip);

	return addr;
}

void peerman_add(struct peer_manager *peers,
		 const struct bp_address *addr_in, bool known_working)
{
	struct bp_address *addr;

	if (peerman_has_addr(peers, addr_in->ip))
		return;

	addr = malloc(sizeof(*addr));
	memcpy(addr, addr_in, sizeof(*addr));

	__peerman_add(peers, addr, !known_working);
}

