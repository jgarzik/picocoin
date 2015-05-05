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
#include <ccoin/serialize.h>
#include <ccoin/net.h>
#include <ccoin/clist.h>
#include <ccoin/compat.h>
#include "picocoin.h"

static unsigned long addr_hash(const void *key)
{
	return djb2_hash(0x1721, key, 16);
}

static bool addr_equal(const void *a, const void *b)
{
	return (memcmp(a, b, 16) == 0);
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

void ser_peer(cstring *s, unsigned int protover, const struct peer *peer)
{
	ser_bp_addr(s, protover, &peer->addr);

	ser_s64(s, peer->last_ok);
	ser_u32(s, peer->n_ok);

	ser_s64(s, peer->last_fail);
	ser_u32(s, peer->n_fail);
}

int peer_cmp(const void *a_, const void *b_, void *user_priv)
{
	const struct peer *a = a_;
	const struct peer *b = b_;

	int64_t a_time = (a->last_ok > a->addr.nTime) ? a->last_ok : a->addr.nTime;
	int64_t b_time = (b->last_ok > b->addr.nTime) ? b->last_ok : b->addr.nTime;
	/* reverse sort, greatest first */
	return (int) (b_time - a_time);
}

static struct peer_manager *peerman_new(void)
{
	struct peer_manager *peers;

	peers = calloc(1, sizeof(*peers));
	if (!peers)
		return NULL;

	peers->map_addr = bp_hashtab_new(addr_hash, addr_equal);
	if (!peers->map_addr) {
		free(peers);
		return NULL;
	}

	return peers;
}

static void peer_ent_free(void *data)
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

	bp_hashtab_unref(peers->map_addr);

	clist_free_ext(peers->addrlist, peer_ent_free);

	memset(peers, 0, sizeof(*peers));
	free(peers);
}

static void __peerman_add(struct peer_manager *peers, struct peer *peer,
			  bool prepend_front)
{
	bn_group(peer->group, &peer->group_len, peer->addr.ip);

	if (prepend_front)
		peers->addrlist = clist_prepend(peers->addrlist, peer);
	else
		peers->addrlist = clist_append(peers->addrlist, peer);

	bp_hashtab_put(peers->map_addr, peer->addr.ip, peer);
}

static bool peerman_has_addr(struct peer_manager *peers,const unsigned char *ip)
{
	return bp_hashtab_get_ext(peers->map_addr, ip, NULL, NULL);
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
	clist *tmp, *seedlist = NULL;
	if (use_dns)
		seedlist = bu_dns_seed_addrs();

	if (debugging)
		fprintf(stderr, "peerman: DNS returned %zu addresses\n",
			clist_length(seedlist));

	clist_shuffle(seedlist);

	/* import seed data into peerman */
	tmp = seedlist;
	while (tmp) {
		struct bp_address *addr = tmp->data;
		tmp = tmp->next;

		peerman_add_addr(peers, addr, true);
		free(addr);
	}
	clist_free(seedlist);

	return peers;
}

static bool ser_peerman(struct peer_manager *peers, int fd)
{
	/* write "magic number" (constant first file record) */
	cstring *rec = message_str(chain->netmagic, "magic.peers", NULL, 0);
	unsigned int rec_len = rec->len;
	ssize_t wrc = write(fd, rec->str, rec_len);

	cstr_free(rec, true);

	if (wrc != rec_len)
		return false;

	if (debugging)
		fprintf(stderr, "peerman: %zu peers to write\n",
			clist_length(peers->addrlist));

	/* write peer list */
	clist *tmp = peers->addrlist;
	while (tmp) {
		struct peer *peer;

		peer = tmp->data;
		tmp = tmp->next;

		cstring *msg_data = cstr_new_sz(sizeof(struct peer));
		ser_peer(msg_data, CADDR_TIME_VERSION, peer);

		rec = message_str(chain->netmagic, "peer",
				  msg_data->str, msg_data->len);

		rec_len = rec->len;
		wrc = write(fd, rec->str, rec_len);

		cstr_free(rec, true);
		cstr_free(msg_data, true);

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

void peerman_sort(struct peer_manager *peers)
{
	peers->addrlist = clist_sort(peers->addrlist, peer_cmp, NULL);
}

struct peer *peerman_pop(struct peer_manager *peers)
{
	struct peer *peer;
	clist *tmp;

	tmp = peers->addrlist;
	if (!tmp)
		return NULL;

	peer = tmp->data;

	peers->addrlist = clist_delete(tmp, tmp);

	bp_hashtab_del(peers->map_addr, peer->addr.ip);

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

	clist *tmp, *seedlist = bu_dns_lookup(NULL, hoststr, port);

	if (debugging)
		fprintf(stderr, "peerman: DNS lookup '%s' returned %zu addresses\n",
			addr_str, clist_length(seedlist));

	/* import seed data into peerman */
	tmp = seedlist;
	while (tmp) {
		struct bp_address *addr = tmp->data;
		tmp = tmp->next;

		peerman_add_addr(peers, addr, true);
	}
	clist_free(seedlist);
}
