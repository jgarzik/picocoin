/* Copyright 2016 Bloq, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */
#include "picocoin-config.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <ccoin/crypto/sha1.h>
#include <ccoin/crypto/sha2.h>
#include <ccoin/crypto/ripemd160.h>
#include <ccoin/crypto/hmac.h>
#include <ccoin/hexcode.h>

static const char *test_data = "Harold of the Rocks";

static void test_sha1(void)
{
	SHA1_CTX ctx;
	unsigned char md1[SHA1_DIGEST_LENGTH];
	unsigned char md2[SHA1_DIGEST_LENGTH];
	static const char *test_hashstr = "455741020672c0e50a41efde48a0b727d441440e";

	sha1_Init(&ctx);
	sha1_Update(&ctx, test_data, strlen(test_data));
	sha1_Final(md1, &ctx);

	sha1_Raw(test_data, strlen(test_data), md2);

	cstring *s1 = str2hex(md1, sizeof(md1));
	cstring *s2 = str2hex(md2, sizeof(md2));

	assert(strcmp(test_hashstr, s1->str) == 0);
	assert(strcmp(test_hashstr, s2->str) == 0);

	cstr_free(s1, true);
	cstr_free(s2, true);
}

static void test_sha256(void)
{
	SHA256_CTX ctx;
	unsigned char md1[SHA256_DIGEST_LENGTH];
	unsigned char md2[SHA256_DIGEST_LENGTH];
	static const char *test_hashstr = "e500c59624947f43d7849943651e41f503fe4a7e1570b90e7b71562ad2293441";

	sha256_Init(&ctx);
	sha256_Update(&ctx, test_data, strlen(test_data));
	sha256_Final(md1, &ctx);

	sha256_Raw(test_data, strlen(test_data), md2);

	cstring *s1 = str2hex(md1, sizeof(md1));
	cstring *s2 = str2hex(md2, sizeof(md2));

	assert(strcmp(test_hashstr, s1->str) == 0);
	assert(strcmp(test_hashstr, s2->str) == 0);

	cstr_free(s1, true);
	cstr_free(s2, true);
}

static void test_sha512(void)
{
	SHA512_CTX ctx;
	unsigned char md1[SHA512_DIGEST_LENGTH];
	unsigned char md2[SHA512_DIGEST_LENGTH];
	static const char *test_hashstr = "ad4630aa2150bd6d6c6ebae4ab9ecfa54b5162dc5aec7b3d426ec2f31992772ec96df66ba720bd6cdc5e62592c02bfcd72a48b161bda00cc92e9da53bf08d2c8";

	sha512_Init(&ctx);
	sha512_Update(&ctx, test_data, strlen(test_data));
	sha512_Final(md1, &ctx);

	sha512_Raw(test_data, strlen(test_data), md2);

	cstring *s1 = str2hex(md1, sizeof(md1));
	cstring *s2 = str2hex(md2, sizeof(md2));

	assert(strcmp(test_hashstr, s1->str) == 0);
	assert(strcmp(test_hashstr, s2->str) == 0);

	cstr_free(s1, true);
	cstr_free(s2, true);
}

static void test_ripemd160(void)
{
	RIPEMD160_CTX ctx;
	unsigned char md1[RIPEMD160_DIGEST_LENGTH];
	unsigned char md2[RIPEMD160_DIGEST_LENGTH];
	static const char *test_hashstr = "62678ae26728a6b9f33b2e13a8d8fb53860d8d27";

	ripemd160_Init(&ctx);
	ripemd160_Update(&ctx, test_data, strlen(test_data));
	ripemd160_Final(md1, &ctx);

	ripemd160(test_data, strlen(test_data), md2);

	cstring *s1 = str2hex(md1, sizeof(md1));
	cstring *s2 = str2hex(md2, sizeof(md2));

	assert(strcmp(test_hashstr, s1->str) == 0);
	assert(strcmp(test_hashstr, s2->str) == 0);

	cstr_free(s1, true);
	cstr_free(s2, true);
}

static void test_hmac(void)
{
	static const char *key = "blockchain blockchain blockchain";
	static const char *res256 = "3b5d1e25fbad8111af6d691bd15210cac2fc7b58039809188294f33250168b6a";
	static const char *res512 = "436a835a8cb769a708903b59ce804e20a770639df7769688c533aafb6f4a1d42d7f88f7b7bdfb6cb47dc5340edbe4342bcc8b76ba9f733fa1bfef24695461922";

	unsigned char md256[SHA256_DIGEST_LENGTH];
	unsigned char md512[SHA512_DIGEST_LENGTH];

	hmac_sha256(key, strlen(key), test_data, strlen(test_data), md256);
	hmac_sha512(key, strlen(key), test_data, strlen(test_data), md512);

	cstring *s256 = str2hex(md256, sizeof(md256));
	cstring *s512 = str2hex(md512, sizeof(md512));

	assert(strcmp(res256, s256->str) == 0);
	assert(strcmp(res512, s512->str) == 0);

	cstr_free(s256, true);
	cstr_free(s512, true);
}

int main (int argc, char *argv[])
{
	test_sha1();
	test_sha256();
	test_sha512();
	test_ripemd160();
	test_hmac();
	return 0;
}
