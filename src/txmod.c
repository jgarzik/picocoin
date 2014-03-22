/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <argp.h>
#include <ctype.h>
#include <glib.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/hexcode.h>

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "blank", 1003, NULL, 0,
	  "Start new, blank transaction. Do not read any input data." },
	{ "locktime", 1001, "LOCKTIME", 0,
	  "Set transaction lock time" },
	{ "nversion", 1002, "VERSION", 0,
	  "Set transaction version" },
	{ "txin", 1004, "TXID:VOUT", 0,
	  "Append a transaction input" },

	{ }
};

static char *opt_locktime;
static char *opt_version;
static char *opt_hexdata;
static bool opt_blank;
static struct bp_tx tx;
static GList *opt_txin;

static const char doc[] =
"txmod - command line interface to modify bitcoin transactions";
static const char args_doc[] =
"HEX-ENCODED-TX";

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, args_doc, doc };

static bool is_digitstr(const char *s)
{
	if (!*s)
		return false;
	while (*s) {
		if (!isdigit(*s))
			return false;
		s++;
	}

	return true;
}

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {

	case 1001:			// --locktime=NNNNN
		opt_locktime = arg;
		break;
	case 1002:			// --nversion=NNNNN
		opt_version = arg;
		break;
	case 1003:			// --blank
		opt_blank = true;
		break;
	case 1004: {			// --txin=TXID:VOUT
		char *colon = strchr(arg, ':');
		if (!colon)
			return ARGP_ERR_UNKNOWN;
		if ((colon - arg) != 64)
			return ARGP_ERR_UNKNOWN;
		if (!is_digitstr(colon + 1))
			return ARGP_ERR_UNKNOWN;

		char hexstr[65];
		memcpy(hexstr, arg, 64);
		hexstr[64] = 0;
		if (!is_hexstr(hexstr, false))
			return ARGP_ERR_UNKNOWN;

		opt_txin = g_list_append(opt_txin, strdup(arg));
		break;
	 }

	case ARGP_KEY_ARG:
		if (opt_hexdata)
			return ARGP_ERR_UNKNOWN;
		opt_hexdata = arg;
		break;

	default:
		return ARGP_ERR_UNKNOWN;
	}

	return 0;
}

static void mutate_locktime(void)
{
	long long ll = strtoll(opt_locktime, NULL, 10);
	if ((ll != 0LL) && (ll < 1395466455LL || ll > 0xffffffffLL)) {
		fprintf(stderr, "invalid lock time %lld\n", ll);
		exit(1);
	}

	tx.nLockTime = (uint32_t) ll;
}

static void mutate_version(void)
{
	int nVersion = atoi(opt_version);
	if (nVersion < 1 || nVersion > 3) {
		fprintf(stderr, "invalid tx version %d\n", nVersion);
		exit(1);
	}

	tx.nVersion = (uint32_t) nVersion;
}

static void append_input(char *txid_str, char *vout_str)
{
	bu256_t txid;
	if (!hex_bu256(&txid, txid_str)) {
		fprintf(stderr, "invalid txid hex\n");
		exit(1);
	}

	unsigned int vout = atoi(vout_str);

	struct bp_txin *txin = calloc(1, sizeof(struct bp_txin));
	if (!txin) {
		fprintf(stderr, "OOM\n");
		exit(1);
	}
	bp_txin_init(txin);

	bu256_copy(&txin->prevout.hash, &txid);
	txin->prevout.n = vout;
	txin->scriptSig = g_string_new(NULL);
	txin->nSequence = 0xffffffffU;

	g_ptr_array_add(tx.vin, txin);
}

static void mutate_inputs(void)
{
	if (!tx.vin)
		tx.vin = g_ptr_array_new_full(8, g_bp_txin_free);

	GList *tmp = opt_txin;
	while (tmp) {
		char *arg = tmp->data;
		tmp = tmp->next;

		size_t alloc_len = strlen(arg) + 1;
		char txid_str[alloc_len];
		strcpy(txid_str, arg);

		char *colon = strchr(txid_str, ':');
		*colon = 0;

		char vout_str[alloc_len];
		strcpy(vout_str, colon + 1);

		append_input(txid_str, vout_str);
	}
}

static void apply_mutations(void)
{
	if (opt_locktime)
		mutate_locktime();
	if (opt_version)
		mutate_version();
	if (opt_txin)
		mutate_inputs();
}

static void read_data(void)
{
	if (!opt_hexdata) {
		fprintf(stderr, "no input data\n");
		exit(1);
	}
	
	GString *txbuf = hex2str(opt_hexdata);
	if (!txbuf) {
		fprintf(stderr, "invalid input data\n");
		exit(1);
	}
	struct const_buffer cbuf = { txbuf->str, txbuf->len };

	if (!deser_bp_tx(&tx, &cbuf)) {
		fprintf(stderr, "TX decode failed\n");
		exit(1);
	}

	g_string_free(txbuf, TRUE);
}

static void write_data(void)
{
	size_t alloc_len = opt_hexdata ? strlen(opt_hexdata) : 512;
	GString *s = g_string_sized_new(alloc_len);
	ser_bp_tx(s, &tx);

	char hexstr[(s->len * 2) + 1];
	encode_hex(hexstr, s->str, s->len);
	printf("%s\n", hexstr);

	g_string_free(s, TRUE);
}

int main (int argc, char *argv[])
{
	error_t aprc;

	aprc = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (aprc) {
		fprintf(stderr, "argp_parse failed: %s\n", strerror(aprc));
		return 1;
	}

	bp_tx_init(&tx);

	if (!opt_blank)
		read_data();
	apply_mutations();
	write_data();

	bp_tx_free(&tx);

	return 0;
}


