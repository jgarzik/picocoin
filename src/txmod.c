/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdint.h>
#include <stdlib.h>
#include <argp.h>
#include <glib.h>
#include <ccoin/core.h>
#include <ccoin/util.h>
#include <ccoin/hexcode.h>

const char *argp_program_version = PACKAGE_VERSION;

static struct argp_option options[] = {
	{ "locktime", 1001, "LOCKTIME", 0,
	  "Set transaction lock time" },
	{ "nversion", 1002, "VERSION", 0,
	  "Set transaction version" },

	{ }
};

static char *opt_locktime;
static char *opt_version;
static char *opt_hexdata;
static struct bp_tx tx;

static const char doc[] =
"txmod - command line interface to modify bitcoin transactions";
static const char args_doc[] =
"HEX-ENCODED-TX";

static error_t parse_opt (int key, char *arg, struct argp_state *state);

static const struct argp argp = { options, parse_opt, args_doc, doc };

static error_t parse_opt (int key, char *arg, struct argp_state *state)
{
	switch(key) {

	case 1001:
		opt_locktime = arg;
		break;
	case 1002:
		opt_version = arg;
		break;

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

static void apply_mutations(void)
{
	if (opt_locktime)
		mutate_locktime();
	if (opt_version)
		mutate_version();
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
	GString *s = g_string_sized_new(strlen(opt_hexdata));
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

	if (!opt_locktime && !opt_version) {
		fprintf(stderr, "nothing to do\n");
		return 1;
	}

	bp_tx_init(&tx);

	read_data();
	apply_mutations();
	write_data();

	bp_tx_free(&tx);

	return 0;
}


