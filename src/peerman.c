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
#include <ccoin/serialize.h>
#include "picocoin.h"

static guint addr_hash(gconstpointer key)
{
	return djb2_hash(0x1721, key, 16);
}

static gboolean addr_equal(gconstpointer a, gconstpointer b)
{
	return memcmp(a, b, 16) == 0 ? TRUE : FALSE;
}

bool deser_peer(unsigned int protover,
		struct peer *peer, struct const_buffer *buf)
{
	peer_free(peer);

	if (!deser_bp_addr(protover, &peer->addr, buf)) return false;

	if (!deser_s64(&peer->last_ok, buf)) return false;
	if (!deser_u32(&peer->n_ok, buf)) return false;

	if (!deser_s64(&peer->last_fail, buf)) return false;
	if (!deser_u32(&peer->n_fail, buf)) return false;

	return true;
}

void ser_peer(GString *s, unsigned int protover, const struct peer *peer)
{
	ser_bp_addr(s, protover, &peer->addr);

	ser_s64(s, peer->last_ok);
	ser_u32(s, peer->n_ok);

	ser_s64(s, peer->last_fail);
	ser_u32(s, peer->n_fail);
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

static void peer_ent_free(gpointer data)
{
	if (!data)
		return;
	struct peer *peer = data;

	peer_free(peer);
	free(peer);
}

void peerman_free(struct peer_manager *peers)
{
	if (!peers)
		return;

	if (peers->map_addr)
		g_hash_table_unref(peers->map_addr);

	g_list_free_full(peers->addrlist, peer_ent_free);

	memset(peers, 0, sizeof(*peers));
	free(peers);
}

static void __peerman_add(struct peer_manager *peers, struct peer *peer,
			  bool prepend_front)
{
	if (prepend_front)
		peers->addrlist = g_list_prepend(peers->addrlist, peer);
	else
		peers->addrlist = g_list_append(peers->addrlist, peer);

	g_hash_table_insert(peers->map_addr, peer->addr.ip, peer);
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

	if (strncmp(msg->hdr.command, "peer", sizeof(msg->hdr.command)))
		return false;

	struct const_buffer buf = { msg->data, msg->hdr.data_len };
	struct peer *peer;

	peer = calloc(1, sizeof(*peer));
	peer_init(peer);

	if (deser_peer(CADDR_TIME_VERSION, peer, &buf) &&
	    !peerman_has_addr(peers, peer->addr.ip))
		__peerman_add(peers, peer, false);
	else {
		peer_free(peer);
		free(peer);
	}

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
		if (!peerman_read_rec(peers, &msg)) {
			fprintf(stderr, "peerman: read record failed\n");
			goto err_out;
		}
	}

	if (!read_ok) {
		fprintf(stderr, "peerman: read I/O failed\n");
		goto err_out;
	}

	free(msg.data);
	close(fd);

	return peers;

err_out:
	peerman_free(peers);
	return NULL;
}

struct peer_manager *peerman_seed(bool use_dns)
{
	struct peer_manager *peers;

	peers = peerman_new();
	if (!peers)
		return NULL;

	/* make DNS query for seed data */
	GList *tmp, *seedlist = NULL;
	if (use_dns)
		seedlist = bu_dns_seed_addrs();

	if (debugging)
		fprintf(stderr, "peerman: DNS returned %u addresses\n",
			g_list_length(seedlist));

	g_list_shuffle(seedlist);

	/* import seed data into peerman */
	tmp = seedlist;
	while (tmp) {
		struct bp_address *addr = tmp->data;
		tmp = tmp->next;

		peerman_add_addr(peers, addr, true);
		free(addr);
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
		struct peer *peer;

		peer = tmp->data;
		tmp = tmp->next;

		GString *msg_data = g_string_sized_new(sizeof(struct peer));
		ser_peer(msg_data, CADDR_TIME_VERSION, peer);

		rec = message_str(chain->netmagic, "peer",
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

struct peer *peerman_pop(struct peer_manager *peers)
{
	struct peer *peer;
	GList *tmp;

	tmp = peers->addrlist;
	if (!tmp)
		return NULL;

	peer = tmp->data;

	peers->addrlist = g_list_delete_link(tmp, tmp);

	g_hash_table_remove(peers->map_addr, peer->addr.ip);

	return peer;
}

void peerman_add(struct peer_manager *peers,
		 const struct peer *peer_in, bool known_working)
{
	if (peerman_has_addr(peers, peer_in->addr.ip))
		return;

	struct peer *peer;
	peer = malloc(sizeof(*peer));
	if (!peer)
		return;

	peer_copy(peer, peer_in);

	__peerman_add(peers, peer, !known_working);
}

void peerman_add_addr(struct peer_manager *peers,
		 const struct bp_address *addr_in, bool known_working)
{
	if (peerman_has_addr(peers, addr_in->ip))
		return;

	struct peer *peer;
	peer = malloc(sizeof(*peer));
	if (!peer)
		return;

	peer_init(peer);
	bp_addr_copy(&peer->addr, addr_in);

	__peerman_add(peers, peer, !known_working);
}

void peerman_addstr(struct peer_manager *peers,
		    const char *addr_str)
{
	char hoststr[64] = {};
	char portstr[16] = {};
	char *space = strchr(addr_str, ' ');
	int port;

	if (space) {
		unsigned int hlen = (space - addr_str);
		if (hlen > (sizeof(hoststr) - 1))
			hlen = sizeof(hoststr) - 1;

		memcpy(hoststr, addr_str, hlen);
		hoststr[hlen] = 0;

		strncpy(portstr, space + 1, sizeof(portstr) - 1);
	} else {
		strncpy(hoststr, addr_str, sizeof(hoststr) - 1);
		strcpy(portstr, "8333");
	}

	port = atoi(portstr);
	if (port < 1 || port > 65535)
		port = 8333;

	GList *tmp, *seedlist = bu_dns_lookup(NULL, hoststr, port);

	if (debugging)
		fprintf(stderr, "peerman: DNS lookup '%s' returned %u addresses\n",
			addr_str, g_list_length(seedlist));

	/* import seed data into peerman */
	tmp = seedlist;
	while (tmp) {
		__peerman_add(peers, tmp->data, true);
		tmp = tmp->next;
	}
	g_list_free(seedlist);
}
