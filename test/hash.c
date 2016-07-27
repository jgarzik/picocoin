/*
 * Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <stdio.h>
#include <string.h>

#include <ccoin/crypto/sha1.h>

static void print_n(const void *_data, size_t len)
{
	const uint8_t *data = (const uint8_t *)_data;
	size_t i;
	for (i = 0; i < len; ++i) {
		printf("%02x", (int)data[i]);
	}
}

static void check_sha1(const uint8_t *data,
		       size_t len,
		       const uint8_t expected[SHA1_DIGEST_LENGTH])
{
	uint8_t digest[SHA1_DIGEST_LENGTH];
	sha1_Raw(data, len, digest);
	if (0 != memcmp(digest, expected, sizeof(digest))) {
		printf("SHA1 for msg 0x%02x%02x... (len %d) broken\n",
		       data[0], data[1], (int )len);
		printf(" expect: "); print_n(expected, SHA1_DIGEST_LENGTH); printf("\n");
		printf(" actual: "); print_n(digest, SHA1_DIGEST_LENGTH); printf("\n");
		abort();
	}
}

static void test_sha1()
{
	/* Let the message be the ASCII string "abc". [file] The resulting
	 * 160-bit message digest is a9993e36 4706816a ba3e2571 7850c26c
	 * 9cd0d89d.
	 */
	{
		const uint8_t msg[] = "abc";

		const uint8_t expect[] = {
			0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a,
			0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c,
			0x9c, 0xd0, 0xd8, 0x9d };
		check_sha1(msg, sizeof(msg)-1, expect);
	}

	/* Let the message be the ASCII string
	 * "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq". [file]
	 * The resulting 160-bit message digest is 84983e44 1c3bd26e
	 * baae4aa1 f95129e5 e54670f1.
	 */
	{
		const uint8_t msg[] =
			"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
		const uint8_t expect[SHA1_DIGEST_LENGTH] = {
			0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e,
			0xba, 0xae, 0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5,
			0xe5, 0x46, 0x70, 0xf1 };
		check_sha1(msg, sizeof(msg)-1, expect);
	}

	/* Let the message be the binary-coded form of the ASCII string
	 * which consists of 1,000,000 repetitions of the character
	 * "a". [file] The resulting SHA-1 message digest is 34aa973c
	 * d4c4daa4 f61eeb2b dbad2731 6534016f.
	 */
	{
		void *msg = malloc(1000000);
		memset(msg, 'a', 1000000);

		const uint8_t expect[SHA1_DIGEST_LENGTH] = {
			0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4,
			0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad, 0x27, 0x31,
			0x65, 0x34, 0x01, 0x6f };
		check_sha1(msg, 1000000, expect);
		free(msg);
	}
}

int main(int argc, char **argv)
{
	test_sha1();

	return 0;
}
