
#include "picocoin-config.h"

#include <string.h>
#include "peerman.h"
#include "mbr.h"
#include "util.h"
#include "coredefs.h"
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

	g_hash_table_insert(peers->map_addr, addr->ip, GUINT_TO_POINTER(1));
}

static bool peerman_read_rec(struct peer_manager *peers,struct p2p_message *msg)
{
	if (strncmp(msg->hdr.command, "CAddress", sizeof(msg->hdr.command)) ||
	    (msg->hdr.data_len != sizeof(struct bp_address)))
		return false;

	struct buffer buf = { msg->data, msg->hdr.data_len };
	struct bp_address *addr;

	addr = calloc(1, sizeof(*addr));

	if (!deser_bp_addr(CADDR_TIME_VERSION, addr, &buf))
		goto err_out;

	if (!g_hash_table_lookup(peers->map_addr, addr->ip))
		__peerman_add(peers, addr, false);
	else
		goto err_out;

	return true;

err_out:
	free(addr);
	return false;
}

struct peer_manager *peerman_read(void)
{
	char *filename = setting("peers");
	if (!filename)
		return NULL;

	void *data = NULL;
	size_t data_len = 0;

	if (!bu_read_file(filename, &data, &data_len, 100 * 1024 * 1024))
		return NULL;

	struct peer_manager *peers;

	peers = peerman_new();

	struct buffer buf = { data, data_len };
	struct mbuf_reader mbr;

	mbr_init(&mbr, &buf);

	while (mbr_read(&mbr)) {
		if (!peerman_read_rec(peers, &mbr.msg)) {
			mbr.error = true;
			break;
		}
	}

	if (mbr.error) {
		peerman_free(peers);
		peers = NULL;
	}

	mbr_free(&mbr);
	free(data);

	return peers;
}

struct peer_manager *peerman_seed(void)
{
	struct peer_manager *peers;

	peers = peerman_new();
	if (!peers)
		return NULL;

	/* make DNS query for seed data */
	GList *tmp, *seedlist = bu_dns_seed_addrs();

	/* import seed data into peerman */
	tmp = seedlist;
	while (tmp) {
		__peerman_add(peers, tmp->data, true);
		tmp = tmp->next;
	}
	g_list_free(seedlist);

	return peers;
}

static GString *ser_peerman(struct peer_manager *peers)
{
	unsigned int peer_count = g_hash_table_size(peers->map_addr);
	GString *s = g_string_sized_new(
		peer_count * (24 + sizeof(struct bp_address)));

	GList *tmp = peers->addrlist;

	while (tmp) {
		struct bp_address *addr;

		addr = tmp->data;
		tmp = tmp->next;

		GString *msg_data = g_string_sized_new(sizeof(struct bp_address));
		ser_bp_addr(msg_data, CADDR_TIME_VERSION, addr);

		GString *rec = message_str(chain->netmagic, "CAddress",
					   msg_data->str, msg_data->len);

		g_string_append_len(s, rec->str, rec->len);

		g_string_free(rec, TRUE);
		g_string_free(msg_data, TRUE);
	}

	return s;
}

bool peerman_write(struct peer_manager *peers)
{
	char *filename = setting("peers");
	if (!filename)
		return false;

	GString *data = ser_peerman(peers);

	bool rc = bu_write_file(filename, data->str, data->len);

	g_string_free(data, TRUE);

	return rc;
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

	if (g_hash_table_lookup(peers->map_addr, addr_in->ip))
		return;

	addr = malloc(sizeof(*addr));
	memcpy(addr, addr_in, sizeof(*addr));

	__peerman_add(peers, addr, !known_working);
}

