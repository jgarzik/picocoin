/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <ccoin/coredefs.h>
#include <ccoin/util.h>
#include <ccoin/compat.h>		/* for mkstemp */

void bu_reverse_copy(unsigned char *dst, const unsigned char *src, size_t len)
{
	unsigned int i;
	for (i = 0; i < len; i++) {
		dst[len - i - 1] = src[i];
	}
}

void bu_Hash(unsigned char *md256, const void *data, size_t data_len)
{
	unsigned char md1[SHA256_DIGEST_LENGTH];

	SHA256(data, data_len, md1);
	SHA256(md1, SHA256_DIGEST_LENGTH, md256);
}

void bu_Hash_(unsigned char *md256,
		     const void *data1, size_t data_len1,
		     const void *data2, size_t data_len2)
{
	SHA256_CTX ctx;
	unsigned char md1[SHA256_DIGEST_LENGTH];

	SHA256_Init(&ctx);
	SHA256_Update(&ctx, data1, data_len1);
	SHA256_Update(&ctx, data2, data_len2);
	SHA256_Final(md1, &ctx);

	SHA256(md1, SHA256_DIGEST_LENGTH, md256);
}

void bu_Hash4(unsigned char *md32, const void *data, size_t data_len)
{
	unsigned char md256[SHA256_DIGEST_LENGTH];

	bu_Hash(md256, data, data_len);
	memcpy(md32, md256, 4);
}

void bu_Hash160(unsigned char *md160, const void *data, size_t data_len)
{
	unsigned char md1[SHA256_DIGEST_LENGTH];

	SHA256(data, data_len, md1);
	RIPEMD160(md1, SHA256_DIGEST_LENGTH, md160);
}

bool bu_read_file(const char *filename, void **data_, size_t *data_len_,
	       size_t max_file_len)
{
	void *data;
	struct stat st;

	*data_ = NULL;
	*data_len_ = 0;

	int fd = file_seq_open(filename);
	if (fd < 0)
		return false;

	if (fstat(fd, &st) < 0)
		goto err_out_fd;

	if (st.st_size > max_file_len)
		goto err_out_fd;

	data = malloc(st.st_size);
	if (!data)
		goto err_out_fd;

	ssize_t rrc = read(fd, data, st.st_size);
	if (rrc != st.st_size)
		goto err_out_mem;

	close(fd);
	fd = -1;

	*data_ = data;
	*data_len_ = st.st_size;

	return true;

err_out_mem:
	free(data);
err_out_fd:
	if (fd >= 0)
		close(fd);
	return false;
}

bool bu_write_file(const char *filename, const void *data, size_t data_len)
{
	char tmpfn[strlen(filename) + 16];
	strcpy(tmpfn, filename);
	strcat(tmpfn, ".XXXXXX");

	int fd = mkstemp(tmpfn);
	if (fd < 0)
		return false;

	ssize_t wrc = write(fd, data, data_len);
	if (wrc != data_len)
		goto err_out_fd;

	close(fd);
	fd = -1;

	if (rename(tmpfn, filename) < 0)
		goto err_out_fd;

	return true;

err_out_fd:
	if (fd >= 0)
		close(fd);
	unlink(tmpfn);
	return false;
}

/* "djb2"-derived hash function */
unsigned long djb2_hash(unsigned long hash, const void *_buf, size_t buflen)
{
	const unsigned char *buf = _buf;
	int c;

	while (buflen > 0) {
		c = *buf++;
		buflen--;

		hash = ((hash << 5) + hash) ^ c; /* hash * 33 ^ c */
	}

	return hash;
}

static void init_rng(void)
{
	static bool done = false;

	if (done)
		return;

	srand(time(NULL));

	done = true;
}

static int random_int_range(int begin, int end)
{
	init_rng();

	int l = end - begin + 1;
	int r = rand() % l;
	return begin + r;
}

void clist_shuffle(clist *l)
{
	unsigned int len = clist_length(l);
	unsigned int idx = 0;

	clist *tmp = l;
	while (tmp) {
		unsigned int ridx = random_int_range(0, len - 1);

		if (ridx != idx) {
			clist *swap = clist_nth(l, ridx);

			void *tmp_data = tmp->data;
			void *swap_data = swap->data;

			tmp->data = swap_data;
			swap->data = tmp_data;
		}

		tmp = tmp->next;
		idx++;
	}
}

void btc_decimal(char *valstr, size_t valstr_sz, int64_t val)
{
	int64_t val_abs = (val < 0) ? -val : val;
	int64_t q = val_abs / COIN;
	int64_t r = val_abs % COIN;

	snprintf(valstr, valstr_sz, "%lld.%08lld",
		 (long long) q,
		 (long long) r);
	valstr[valstr_sz - 1] = 0;

	while ((valstr[0]) && (valstr[strlen(valstr) - 1] == '0'))
		valstr[strlen(valstr) - 1] = 0;

	if (valstr[strlen(valstr) - 1] == '.') {
		valstr[strlen(valstr)] = '0';
		valstr[valstr_sz - 1] = 0;	/* for rare edge case */
	}
}

unsigned long czstr_hash(const void *p)
{
	size_t slen = strlen(p ? p : "");
	return djb2_hash(0x8088, p, slen);
}

bool czstr_equal(const void *a, const void *b)
{
	size_t a_len = strlen(a ? a : "");
	size_t b_len = strlen(b ? b : "");
	if (a_len != b_len)
		return false;

	return (memcmp(a, b, a_len) == 0);
}

