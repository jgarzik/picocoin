/* Copyright 2016 BitPay, Inc.
 * Copyright 2016 Duncan Tebbs
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/hdkeys.h>

#include <assert.h>
#include <ccoin/base58.h>
#include <openssl/err.h>

#define MAIN_PUBLIC 0x1EB28804
#define MAIN_PRIVATE 0xE4AD8804

static void print_n(const void *_data, size_t len)
{
	const uint8_t *data = (const uint8_t *)_data;
	size_t i;
	for (i = 0; i < len; ++i) {
		printf("%02x", (int)data[i]);
	}
}

#define NEWLINE printf("\n")

#define SPACE printf(" ")

struct hd_extended_key_serialized {
	uint8_t data[78];
};

static bool read_ek_ser_from_base58(const char *base58,
				    struct hd_extended_key_serialized *out)
{
	cstring *str = base58_decode(base58);
	if (str->len == 82) {
		memcpy(out->data, str->str, 78);
		cstr_free(str, true);
		return true;
	}

	cstr_free(str, true);
	return false;
}

static bool write_ek_ser_pub(struct hd_extended_key_serialized *out,
			     const struct hd_extended_key *ek)
{
	cstring s = { (char *)(out->data), 0, sizeof(out->data) + 1 };
	return hd_extended_key_ser_pub(ek, &s);
}

static bool write_ek_ser_prv(struct hd_extended_key_serialized *out,
			     const struct hd_extended_key *ek)
{
	cstring s = { (char *)(out->data), 0, sizeof(out->data) + 1 };
	return hd_extended_key_ser_priv(ek, &s);
}

static bool compare_serialized_pub(const struct hd_extended_key *ek,
				   const struct hd_extended_key_serialized *ser)
{
	struct hd_extended_key_serialized ek_pub;
	if (write_ek_ser_pub(&ek_pub, ek)) {
		return 0 == memcmp(ek_pub.data, ser->data, sizeof(ser->data));
	}
	return false;
}

static bool compare_serialized_prv(const struct hd_extended_key *ek,
				   const struct hd_extended_key_serialized *ser)
{
	struct hd_extended_key_serialized ek_prv;
	if (write_ek_ser_prv(&ek_prv, ek)) {
		return 0 == memcmp(ek_prv.data, ser->data, sizeof(ser->data));
	}
	return false;
}

static bool check_keys_match(const struct hd_extended_key *ekA,
			     const struct hd_extended_key *ekB)
{
	void *pubkeyA;
	size_t pubkeyA_len;
	void *pubkeyB;
	size_t pubkeyB_len;
	bool result = false;
	if (bp_pubkey_get(&ekA->key, &pubkeyA, &pubkeyA_len)) {
		if (bp_pubkey_get(&ekB->key, &pubkeyB, &pubkeyB_len)) {
			result = (pubkeyB_len == pubkeyA_len) &&
				(0 == memcmp(pubkeyA, pubkeyB, pubkeyA_len));
			free(pubkeyB);
		}
		free(pubkeyA);
	}

	return result;
}

static void print_ek_public(const struct hd_extended_key *ek)
{
	printf(" version   : 0x%08x\n", ek->version);
	printf(" depth     : %d\n", ek->depth);
	printf(" parent    : 0x");
	print_n(ek->parent_fingerprint, 4); NEWLINE;
	printf(" index     : %d\n", ek->index);
	printf(" chaincode : ");
	print_n(ek->chaincode.data, 32); NEWLINE;

	void *pub;
	size_t pub_len = 0;
	bp_pubkey_get(&ek->key, &pub, &pub_len);
	printf(" pub key   : ");
	print_n(pub, pub_len); NEWLINE;
	free(pub);
}

#if 0
static void print_n_base58(const void *data, size_t len)
{
	cstring *b58 = base58_encode(data, len);
	printf("%s", b58->str);
	cstr_free(b58, true);
}
#endif

#if 0
static void print_from_base58(const char *str)
{
	cstring *out_str = base58_decode(str);
	/* *out= out_str->str; */
	/* *out_len = out_str->len; */
	print_n(out_str->str, out_str->len);
	cstr_free(out_str, true);
}
#endif

#if 0
static void print_from_base58_key(const char *str)
{
	cstring *out_str = base58_decode(str);
	/* *out= out_str->str; */
	/* *out_len = out_str->len; */
	uint8_t *d = (uint8_t *)(out_str->str);
	print_n(d, 4); SPACE; // version
	print_n(d + 4, 1); SPACE; // depth
	print_n(d + 5, 4); SPACE; // parent fingerprint
	print_n(d + 9, 4); SPACE; // idx
	print_n(d + 13, 32); SPACE; // chain code
	print_n(d + 45, 33); SPACE; // key

	/* print_n(out_str->str, out_str->len); */
	cstr_free(out_str, true);
}
#endif

void print_64(const void *data)
{
	print_n(data, 64);
}

// -----------------------------------------------------------------------------
// Test Vector Data
// -----------------------------------------------------------------------------

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_vector_1

// Seed (hex): 000102030405060708090a0b0c0d0e0f
static const uint8_t s_tv1_seed[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
static const char s_tv1_m_xpub[] = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8";
static const char s_tv1_m_xprv[] = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
static const char s_tv1_m_0H_xpub[] = "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw";
static const char s_tv1_m_0H_xprv[] = "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7";
static const char s_tv1_m_0H_1_xpub[] = "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ";
static const char s_tv1_m_0H_1_xprv[] = "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs";
static const char s_tv1_m_0H_1_2H_xpub[] = "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5";
static const char s_tv1_m_0H_1_2H_xprv[] = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM";
static const char s_tv1_m_0H_1_2H_2_xpub[] = "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV";
static const char s_tv1_m_0H_1_2H_2_xprv[] = "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334";
static const char s_tv1_m_0H_1_2H_2_1000000000_xpub[] = "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy";
static const char s_tv1_m_0H_1_2H_2_1000000000_xprv[] = "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76";

// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Test_vector_2

// Seed (hex): fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
static const uint8_t s_tv2_seed[] = {
	0xff, 0xfc, 0xf9, 0xf6, 0xf3, 0xf0, 0xed, 0xea,
	0xe7, 0xe4, 0xe1, 0xde, 0xdb, 0xd8, 0xd5, 0xd2,
	0xcf, 0xcc, 0xc9, 0xc6, 0xc3, 0xc0, 0xbd, 0xba,
	0xb7, 0xb4, 0xb1, 0xae, 0xab, 0xa8, 0xa5, 0xa2,
	0x9f, 0x9c, 0x99, 0x96, 0x93, 0x90, 0x8d, 0x8a,
	0x87, 0x84, 0x81, 0x7e, 0x7b, 0x78, 0x75, 0x72,
	0x6f, 0x6c, 0x69, 0x66, 0x63, 0x60, 0x5d, 0x5a,
	0x57, 0x54, 0x51, 0x4e, 0x4b, 0x48, 0x45, 0x42,
};
static const char s_tv2_m_xpub[] = "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB";
static const char s_tv2_m_xprv[] = "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U";
static const char s_tv2_m_0_xpub[] = "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH";
static const char s_tv2_m_0_xprv[] = "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt";
static const char s_tv2_m_0_2147483647H_xpub[] = "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a";
static const char s_tv2_m_0_2147483647H_xprv[] = "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9";
static const char s_tv2_m_0_2147483647H_1_xpub[] = "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon";
static const char s_tv2_m_0_2147483647H_1_xprv[] = "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef";
static const char s_tv2_m_0_2147483647H_1_2147483646H_xpub[] = "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL";
static const char s_tv2_m_0_2147483647H_1_2147483646H_xprv[] = "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc";
static const char s_tv2_m_0_2147483647H_1_2147483646H_2_xpub[] = "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt";
static const char s_tv2_m_0_2147483647H_1_2147483646H_2_xprv[] = "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j";

// -----------------------------------------------------------------------------

static void test_extended_key()
{
	printf("TEST: test_extended_key\n");

	// Check we get sensible results when parsing some test vector data

	struct hd_extended_key pub;
	assert(hd_extended_key_init(&pub));
	{
		cstring *tv1data = base58_decode(s_tv1_m_xpub);
		assert(hd_extended_key_deser(&pub, tv1data->str, tv1data->len));
		cstr_free(tv1data, true);
	}

	struct hd_extended_key priv;
	assert(hd_extended_key_init(&priv));
	{
		cstring *tv1data = base58_decode(s_tv1_m_xprv);
		assert(hd_extended_key_deser(&priv, tv1data->str, tv1data->len));
		cstr_free(tv1data, true);
	}

	printf("PUB:\n");
	print_ek_public(&pub);

	printf("PRV:\n");
	print_ek_public(&priv);

	// Check we get the same codechains

	assert(0 == memcmp(pub.chaincode.data, priv.chaincode.data, 32));

	hd_extended_key_free(&priv);
	hd_extended_key_free(&pub);
}

static void test_serialize()
{
	printf("TEST: test_serialize\n");

	const char seed[] = "picocoin test seed";

	struct hd_extended_key m;
	struct hd_extended_key_serialized m_xpub;
	struct hd_extended_key_serialized m_xprv;

	{
		assert(hd_extended_key_init(&m));
		assert(hd_extended_key_generate_master(&m, seed, sizeof(seed)));
		assert(0 == m.depth);
		assert(0 == m.index);
		assert(write_ek_ser_pub(&m_xpub, &m));
		assert(write_ek_ser_prv(&m_xprv, &m));
	}

	// Check that there are no gaps in serialized data

	{
		struct hd_extended_key_serialized m_xpub_A;
		struct hd_extended_key_serialized m_xpub_B;

		memset(m_xpub_A.data, 0xff, sizeof(m_xpub_A.data));
		assert(write_ek_ser_pub(&m_xpub_A, &m));
		memset(m_xpub_B.data, 0x00, sizeof(m_xpub_B.data));
		assert(write_ek_ser_pub(&m_xpub_B, &m));
		assert(0 == memcmp(m_xpub_A.data, m_xpub_B.data, sizeof(m_xpub_B.data)));
	}

	{
		struct hd_extended_key_serialized m_xprv_A;
		struct hd_extended_key_serialized m_xprv_B;

		memset(m_xprv_A.data, 0xff, sizeof(m_xprv_A.data));
		assert(write_ek_ser_prv(&m_xprv_A, &m));
		memset(m_xprv_B.data, 0x00, sizeof(m_xprv_B.data));
		assert(write_ek_ser_prv(&m_xprv_B, &m));
		assert(0 == memcmp(m_xprv_A.data, m_xprv_B.data, sizeof(m_xprv_B.data)));
	}

	// generate child keys 1 and 2H, keep serialized version for
	// comparison

	struct hd_extended_key m_1;
	struct hd_extended_key_serialized m_1_xpub;
	struct hd_extended_key_serialized m_1_xprv;

	struct hd_extended_key m_2H;
	struct hd_extended_key_serialized m_2H_xpub;
	struct hd_extended_key_serialized m_2H_xprv;

	{
		assert(hd_extended_key_init(&m_1));
		assert(hd_extended_key_generate_child(&m, 1, &m_1));
		assert(write_ek_ser_pub(&m_1_xpub, &m_1));
		assert(write_ek_ser_prv(&m_1_xprv, &m_1));

		assert(hd_extended_key_init(&m_2H));
		assert(hd_extended_key_generate_child(&m, 0x80000002, &m_2H));
		assert(write_ek_ser_pub(&m_2H_xpub, &m_2H));
		assert(write_ek_ser_prv(&m_2H_xprv, &m_2H));
	}

	// read back in, re-serialize and check the memory

	{
		struct hd_extended_key m_1_;
		struct hd_extended_key_serialized m_1_xpub_;
		struct hd_extended_key_serialized m_1_xprv_;
		assert(hd_extended_key_init(&m_1_));
		assert(hd_extended_key_deser(&m_1_, m_1_xprv.data, sizeof(m_1_xprv)));
		assert(write_ek_ser_pub(&m_1_xpub_, &m_1_));
		assert(write_ek_ser_prv(&m_1_xprv_, &m_1_));

		assert(0 == memcmp(&m_1_xpub, &m_1_xpub_, sizeof(m_1_xpub_)));
		assert(0 == memcmp(&m_1_xprv, &m_1_xprv_, sizeof(m_1_xprv_)));

		hd_extended_key_free(&m_1_);
	}

	{
		struct hd_extended_key m_2H_;
		struct hd_extended_key_serialized m_2H_xpub_;
		struct hd_extended_key_serialized m_2H_xprv_;
		assert(hd_extended_key_init(&m_2H_));
		assert(hd_extended_key_deser(&m_2H_, m_2H_xprv.data, sizeof(m_2H_xprv)));
		assert(write_ek_ser_pub(&m_2H_xpub_, &m_2H_));
		assert(write_ek_ser_prv(&m_2H_xprv_, &m_2H_));

		assert(0 == memcmp(&m_2H_xpub, &m_2H_xpub_, sizeof(m_2H_xpub_)));
		assert(0 == memcmp(&m_2H_xprv, &m_2H_xprv_, sizeof(m_2H_xprv_)));

		hd_extended_key_free(&m_2H_);
	}

	// read back master, generate child, check prv and pub

	{
		struct hd_extended_key m_;
		struct hd_extended_key m_1_;
		struct hd_extended_key m_2H_;

		assert(hd_extended_key_init(&m_));
		assert(hd_extended_key_deser(&m_, m_xprv.data, sizeof(m_xprv)));

		assert(hd_extended_key_init(&m_1_));
		assert(hd_extended_key_generate_child(&m_, 1, &m_1_));
		assert(check_keys_match(&m_1, &m_1_));

		assert(hd_extended_key_init(&m_2H_));
		assert(hd_extended_key_generate_child(&m_, 0x80000002, &m_2H_));
		assert(check_keys_match(&m_2H, &m_2H_));

		hd_extended_key_free(&m_2H_);
		hd_extended_key_free(&m_1_);
		hd_extended_key_free(&m_);
	}

	// read back master from xpub and generate child.  ensure prv keys
	// can't be retrieved but public keys match.

	{
		struct hd_extended_key m_;
		struct hd_extended_key m_1_;
		uint8_t priv[32];

		assert(hd_extended_key_init(&m_));
		assert(hd_extended_key_deser(&m_, m_xpub.data, sizeof(m_xpub)));
		assert(!bp_key_secret_get(&priv[0], sizeof(priv), &m_.key));

		assert(hd_extended_key_init(&m_1_));
		assert(hd_extended_key_generate_child(&m_, 1, &m_1_));
		assert(!bp_key_secret_get(&priv[0], sizeof(priv), &m_1_.key));

		assert(check_keys_match(&m_1, &m_1_));

		hd_extended_key_free(&m_1_);
		hd_extended_key_free(&m_);
	}

	// read back child from xpub.  ensure no hardened children can be
	// generated.

	{
		struct hd_extended_key m_2H_;
		struct hd_extended_key m_2H_3H_;
		assert(hd_extended_key_init(&m_2H_));
		assert(hd_extended_key_deser(&m_2H_, m_2H_xpub.data, sizeof(m_2H_xpub)));

		assert(hd_extended_key_init(&m_2H_3H_));
		assert(!hd_extended_key_generate_child(&m_2H_, 0x80000003, &m_2H_));

		hd_extended_key_free(&m_2H_3H_);
		hd_extended_key_free(&m_2H_);
	}

	hd_extended_key_free(&m_2H);
	hd_extended_key_free(&m_1);
	hd_extended_key_free(&m);
}

static void test_vector_1()
{
	struct hd_extended_key_serialized tv1_m_xpub;
	read_ek_ser_from_base58(s_tv1_m_xpub, &tv1_m_xpub);
	struct hd_extended_key_serialized tv1_m_xprv;
	read_ek_ser_from_base58(s_tv1_m_xprv, &tv1_m_xprv);
	struct hd_extended_key_serialized tv1_m_0H_xpub;
	read_ek_ser_from_base58(s_tv1_m_0H_xpub, &tv1_m_0H_xpub);
	struct hd_extended_key_serialized tv1_m_0H_xprv;
	read_ek_ser_from_base58(s_tv1_m_0H_xprv, &tv1_m_0H_xprv);
	struct hd_extended_key_serialized tv1_m_0H_1_xpub;
	read_ek_ser_from_base58(s_tv1_m_0H_1_xpub, &tv1_m_0H_1_xpub);
	struct hd_extended_key_serialized tv1_m_0H_1_xprv;
	read_ek_ser_from_base58(s_tv1_m_0H_1_xprv, &tv1_m_0H_1_xprv);
	struct hd_extended_key_serialized tv1_m_0H_1_2H_xpub;
	read_ek_ser_from_base58(s_tv1_m_0H_1_2H_xpub, &tv1_m_0H_1_2H_xpub);
	struct hd_extended_key_serialized tv1_m_0H_1_2H_xprv;
	read_ek_ser_from_base58(s_tv1_m_0H_1_2H_xprv, &tv1_m_0H_1_2H_xprv);
	struct hd_extended_key_serialized tv1_m_0H_1_2H_2_xpub;
	read_ek_ser_from_base58(s_tv1_m_0H_1_2H_2_xpub, &tv1_m_0H_1_2H_2_xpub);
	struct hd_extended_key_serialized tv1_m_0H_1_2H_2_xprv;
	read_ek_ser_from_base58(s_tv1_m_0H_1_2H_2_xprv, &tv1_m_0H_1_2H_2_xprv);
	struct hd_extended_key_serialized tv1_m_0H_1_2H_2_1000000000_xpub;
	read_ek_ser_from_base58(s_tv1_m_0H_1_2H_2_1000000000_xpub,
				&tv1_m_0H_1_2H_2_1000000000_xpub);
	struct hd_extended_key_serialized tv1_m_0H_1_2H_2_1000000000_xprv;
	read_ek_ser_from_base58(s_tv1_m_0H_1_2H_2_1000000000_xprv,
				&tv1_m_0H_1_2H_2_1000000000_xprv);

	printf("TEST: test_vector_1\n");

	// Chain m

	struct hd_extended_key m;
	assert(hd_extended_key_init(&m));
	assert(hd_extended_key_generate_master(&m, s_tv1_seed,
					       sizeof(s_tv1_seed)));
	assert(compare_serialized_pub(&m, &tv1_m_xpub));
	assert(compare_serialized_prv(&m, &tv1_m_xprv));

	// Chain m/0H

	struct hd_extended_key m_0H;
	assert(hd_extended_key_init(&m_0H));
	assert(hd_extended_key_generate_child(&m, 0x80000000, &m_0H));
	assert(compare_serialized_pub(&m_0H, &tv1_m_0H_xpub));
	assert(compare_serialized_prv(&m_0H, &tv1_m_0H_xprv));

	// Chain m/0H/1

	struct hd_extended_key m_0H_1;
	assert(hd_extended_key_init(&m_0H_1));
	assert(hd_extended_key_generate_child(&m_0H, 0x00000001, &m_0H_1));
	assert(compare_serialized_pub(&m_0H_1, &tv1_m_0H_1_xpub));
	assert(compare_serialized_prv(&m_0H_1, &tv1_m_0H_1_xprv));

	// Chain m/0H/1/2H

	struct hd_extended_key m_0H_1_2H;
	assert(hd_extended_key_init(&m_0H_1_2H));
	assert(hd_extended_key_generate_child(&m_0H_1, 0x80000002, &m_0H_1_2H));
	assert(compare_serialized_pub(&m_0H_1_2H, &tv1_m_0H_1_2H_xpub));
	assert(compare_serialized_prv(&m_0H_1_2H, &tv1_m_0H_1_2H_xprv));

	// Chain m/0H/1/2H/2

	struct hd_extended_key m_0H_1_2H_2;
	assert(hd_extended_key_init(&m_0H_1_2H_2));
	assert(hd_extended_key_generate_child(&m_0H_1_2H, 0x00000002,
					      &m_0H_1_2H_2));
	assert(compare_serialized_pub(&m_0H_1_2H_2, &tv1_m_0H_1_2H_2_xpub));
	assert(compare_serialized_prv(&m_0H_1_2H_2, &tv1_m_0H_1_2H_2_xprv));

	// Chain m/0H/1/2H/2/1000000000

	struct hd_extended_key m_0H_1_2H_2_1000000000;
	assert(hd_extended_key_init(&m_0H_1_2H_2_1000000000));
	assert(hd_extended_key_generate_child(&m_0H_1_2H_2, 1000000000,
					      &m_0H_1_2H_2_1000000000));
	assert(compare_serialized_pub(&m_0H_1_2H_2_1000000000,
				      &tv1_m_0H_1_2H_2_1000000000_xpub));
	assert(compare_serialized_prv(&m_0H_1_2H_2_1000000000,
				      &tv1_m_0H_1_2H_2_1000000000_xprv));

	hd_extended_key_free(&m_0H_1_2H_2_1000000000);
	hd_extended_key_free(&m_0H_1_2H_2);
	hd_extended_key_free(&m_0H_1_2H);
	hd_extended_key_free(&m_0H_1);
	hd_extended_key_free(&m_0H);
	hd_extended_key_free(&m);
}

static void test_vector_2()
{
	struct hd_extended_key_serialized tv2_m_xpub;
	read_ek_ser_from_base58(s_tv2_m_xpub, &tv2_m_xpub);
	struct hd_extended_key_serialized tv2_m_xprv;
	read_ek_ser_from_base58(s_tv2_m_xprv, &tv2_m_xprv);
	struct hd_extended_key_serialized tv2_m_0_xpub;
	read_ek_ser_from_base58(s_tv2_m_0_xpub, &tv2_m_0_xpub);
	struct hd_extended_key_serialized tv2_m_0_xprv;
	read_ek_ser_from_base58(s_tv2_m_0_xprv, &tv2_m_0_xprv);
	struct hd_extended_key_serialized tv2_m_0_2147483647H_xpub;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_xpub,
				&tv2_m_0_2147483647H_xpub);
	struct hd_extended_key_serialized tv2_m_0_2147483647H_xprv;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_xprv,
				&tv2_m_0_2147483647H_xprv);
	struct hd_extended_key_serialized tv2_m_0_2147483647H_1_xpub;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_1_xpub,
				&tv2_m_0_2147483647H_1_xpub);
	struct hd_extended_key_serialized tv2_m_0_2147483647H_1_xprv;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_1_xprv,
				&tv2_m_0_2147483647H_1_xprv);
	struct hd_extended_key_serialized
		tv2_m_0_2147483647H_1_2147483646H_xpub;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_1_2147483646H_xpub,
				&tv2_m_0_2147483647H_1_2147483646H_xpub);
	struct hd_extended_key_serialized
		tv2_m_0_2147483647H_1_2147483646H_xprv;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_1_2147483646H_xprv,
				&tv2_m_0_2147483647H_1_2147483646H_xprv);
	struct hd_extended_key_serialized
		tv2_m_0_2147483647H_1_2147483646H_2_xpub;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_1_2147483646H_2_xpub,
				&tv2_m_0_2147483647H_1_2147483646H_2_xpub);
	struct hd_extended_key_serialized
		tv2_m_0_2147483647H_1_2147483646H_2_xprv;
	read_ek_ser_from_base58(s_tv2_m_0_2147483647H_1_2147483646H_2_xprv,
				&tv2_m_0_2147483647H_1_2147483646H_2_xprv);

	printf("TEST: test_vector_2\n");

	// Chain m

	struct hd_extended_key m;
	assert(hd_extended_key_init(&m));
	assert(hd_extended_key_generate_master(&m, s_tv2_seed,
					       sizeof(s_tv2_seed)));
	assert(compare_serialized_pub(&m, &tv2_m_xpub));
	assert(compare_serialized_prv(&m, &tv2_m_xprv));

	// Chain m/0

	struct hd_extended_key m_0;
	assert(hd_extended_key_init(&m_0));
	assert(hd_extended_key_generate_child(&m, 0x0, &m_0));
	assert(compare_serialized_pub(&m_0, &tv2_m_0_xpub));
	assert(compare_serialized_prv(&m_0, &tv2_m_0_xprv));

	// Chain m/0/2147483647H

	struct hd_extended_key m_0_2147483647H;
	assert(hd_extended_key_init(&m_0_2147483647H));
	assert(hd_extended_key_generate_child(&m_0, 0x80000000 | 2147483647,
					      &m_0_2147483647H));
	assert(compare_serialized_pub(&m_0_2147483647H,
				      &tv2_m_0_2147483647H_xpub));
	assert(compare_serialized_prv(&m_0_2147483647H,
				      &tv2_m_0_2147483647H_xprv));

	// Chain m/0/2147483647H/1

	struct hd_extended_key m_0_2147483647H_1;
	assert(hd_extended_key_init(&m_0_2147483647H_1));
	assert(hd_extended_key_generate_child(&m_0_2147483647H, 1,
					      &m_0_2147483647H_1));
	assert(compare_serialized_pub(&m_0_2147483647H_1,
				      &tv2_m_0_2147483647H_1_xpub));
	assert(compare_serialized_prv(&m_0_2147483647H_1,
				      &tv2_m_0_2147483647H_1_xprv));

	// Chain m/0/2147483647H/1/2147483646H

	struct hd_extended_key m_0_2147483647H_1_2147483646H;
	assert(hd_extended_key_init(&m_0_2147483647H_1_2147483646H));
	assert(hd_extended_key_generate_child(&m_0_2147483647H_1,
					      0x80000000 | 2147483646,
					      &m_0_2147483647H_1_2147483646H));
	assert(compare_serialized_pub(&m_0_2147483647H_1_2147483646H,
				      &tv2_m_0_2147483647H_1_2147483646H_xpub));
	assert(compare_serialized_prv(&m_0_2147483647H_1_2147483646H,
				      &tv2_m_0_2147483647H_1_2147483646H_xprv));

	// Chain m/0/2147483647H/1/2147483646H/2

	struct hd_extended_key m_0_2147483647H_1_2147483646H_2;
	assert(hd_extended_key_init(&m_0_2147483647H_1_2147483646H_2));
	assert(hd_extended_key_generate_child(&m_0_2147483647H_1_2147483646H, 2,
					      &m_0_2147483647H_1_2147483646H_2));
	assert(compare_serialized_pub(&m_0_2147483647H_1_2147483646H_2,
				      &tv2_m_0_2147483647H_1_2147483646H_2_xpub));
	assert(compare_serialized_prv(&m_0_2147483647H_1_2147483646H_2,
				      &tv2_m_0_2147483647H_1_2147483646H_2_xprv));

	hd_extended_key_free(&m_0_2147483647H_1_2147483646H_2);
	hd_extended_key_free(&m_0_2147483647H_1_2147483646H);
	hd_extended_key_free(&m_0_2147483647H_1);
	hd_extended_key_free(&m_0_2147483647H);
	hd_extended_key_free(&m_0);
	hd_extended_key_free(&m);
}

int main(int argc, char **argv)
{
	test_extended_key();
	test_serialize();
	test_vector_1();
	test_vector_2();

	// Keep valgrind happy
	ERR_remove_state(0);

	return 0;
}
