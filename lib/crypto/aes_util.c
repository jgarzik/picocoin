/* Copyright 2012 exMULTI, Inc.
 * Distributed under the MIT/X11 software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#include <ccoin/crypto/aes_util.h>
#include <ccoin/crypto/ctaes.h>         // for AES256_ctx, AES256_encrypt, etc
#include <ccoin/crypto/sha2.h>          // for sha512_Update, sha512_Final, etc
#include <ccoin/util.h>                 // for bu_read_file, bu_write_file

#include <stdlib.h>                     // for free
#include <string.h>                     // for memcpy, memset


int BytesToKeySHA512AES(unsigned char *salt, unsigned char *key_data, size_t key_data_len, int count, unsigned char *key, unsigned char *iv)
{
    // This mimics the behavior of openssl's EVP_BytesToKey with an aes256cbc
    // cipher and sha512 message digest. Because sha512's output size (64b) is
    // greater than the aes256 block size (16b) + aes256 key size (32b),
    // there's no need to process more than once (D_0).

    if(!count || !key || !iv)
        return 0;

    unsigned char _buf0[64];
    unsigned char _buf1[64];

    SHA512_CTX ctx;
    sha512_Init(&ctx);
    sha512_Update(&ctx, key_data, key_data_len);
    sha512_Update(&ctx, salt, 8);
    sha512_Final(_buf0, &ctx);

    unsigned char *swap;
    unsigned char *buf0 = _buf0;
    unsigned char *buf1 = _buf1;
    int i;

    for(i = 0; i != count - 1; i++) {
        sha512_Raw(buf0, 64, buf1);
        swap = buf1;
        buf1 = buf0;
        buf0 = swap;
    }
    memset(buf1, 0, 64);
    memcpy(key, buf0, 32);
    memcpy(iv, buf0 + 32, 16);
    memset(buf0, 0, 64);

    return 32;
}

static int AES256CBCEncrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, int size, bool pad, unsigned char* out)
{
    int written = 0;
    int padsize = size % 16;
    unsigned char mixed[16];

    if (!data || !size || !out)
        return 0;

    if (!pad && padsize != 0)
        return 0;

    memcpy(mixed, iv, 16);

    // Write all but the last block
    int i;
    AES256_ctx ctx;
    AES256_init(&ctx, key);
    while (written + 16 <= size) {
        for (i = 0; i != 16; i++)
            mixed[i] ^= *data++;
        AES256_encrypt(&ctx, 1, out + written, mixed);
        memcpy(mixed, out + written, 16);
        written += 16;
    }
    if (pad) {
        // For all that remains, pad each byte with the value of the remaining
        // space. If there is none, pad by a full block.
        for (i = 0; i != padsize; i++)
            mixed[i] ^= *data++;
        for (i = padsize; i != 16; i++)
            mixed[i] ^= 16 - padsize;
        AES256_encrypt(&ctx, 1, out + written, mixed);
        written += 16;
    }
    return written;
}

static int AES256CBCDecrypt(const unsigned char* key, const unsigned char* iv, const unsigned char* data, int size, bool pad, unsigned char* out)
{
    unsigned char padsize = 0;
    int written = 0;
    int i = 0;
    bool fail = false;
    const unsigned char* prev = iv;

    if (!data || !size || !out)
        return 0;

    if (size % 16 != 0)
        return 0;

    // Decrypt all data. Padding will be checked in the output.
    AES256_ctx ctx;
    AES256_init(&ctx, key);
    while (written != size) {
        AES256_decrypt(&ctx, 1, out, data + written);
        for (i = 0; i != 16; i++)
            *out++ ^= prev[i];
        prev = data + written;
        written += 16;
    }

    // When decrypting padding, attempt to run in constant-time
    if (pad) {
        // If used, padding size is the value of the last decrypted byte. For
        // it to be valid, It must be between 1 and 16.
        padsize = *--out;
        fail = !padsize | (padsize > 16);

        // If not well-formed, treat it as though there's no padding.
        padsize *= !fail;

        // All padding must equal the last byte otherwise it's not well-formed
        for (i = 16; i != 0; i--)
            fail |= ((i > 16 - padsize) & (*out-- != padsize));

        written -= padsize;
    }
    return written * !fail;
}

cstring *read_aes_file(const char *filename, void *key_data, size_t key_data_len,
		       size_t max_file_len)
{
    void *ciphertext = NULL;
    size_t ct_len = 0;
    bool pad = true;
    cstring *rs = NULL;

    if (bu_read_file(filename, &ciphertext, &ct_len, max_file_len)) {
        size_t pt_len = ct_len;
        unsigned char plaintext[pt_len];

        // 25000 rounds is just under 0.1 seconds on a 1.86 GHz Pentium M
        // ie slightly lower than the lowest hardware we need bother supporting
        int nrounds = 1721;
        unsigned int salt[] = { 4185398345U, 2729682459U };
        unsigned char key[32], iv[16];

        /*
         * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
         * nrounds is the number of times the we hash the material. More rounds are more secure but
         * slower.
         */
        if (BytesToKeySHA512AES((unsigned char *)salt, key_data,
                key_data_len, nrounds, key, iv) == 32) {
            if (AES256CBCDecrypt(key, iv, ciphertext, ct_len, pad, plaintext) > 0) {
                if (pad)
                    pt_len -= plaintext[pt_len - 1];

                rs = cstr_new_buf(plaintext, pt_len);
            }
        }
        memset(key, 0, 32);
        memset(iv, 0, 16);
        memset(plaintext, 0, ct_len);
    }
    free(ciphertext);

    return rs;
}

bool write_aes_file(const char *filename, void *key_data, size_t key_data_len,
		    const void *plaintext, size_t pt_len)
{
    size_t ct_len = pt_len;
    unsigned char ciphertext[ct_len];
    bool pad = true;
    bool rc = false;

    // 25000 rounds is just under 0.1 seconds on a 1.86 GHz Pentium M
    // ie slightly lower than the lowest hardware we need bother supporting
    int nrounds = 1721;
    unsigned int salt[] = { 4185398345U, 2729682459U };
    unsigned char key[32], iv[16];

    /*
     * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
     * nrounds is the number of times the we hash the material. More rounds are more secure but
     * slower.
     */
    if (BytesToKeySHA512AES((unsigned char *)salt, key_data,
            key_data_len, nrounds, key, iv) == 32)
        if ((ct_len = AES256CBCEncrypt(key, iv, plaintext, pt_len, pad,
                ciphertext)) > 0 )
            rc = bu_write_file(filename, &ciphertext, ct_len);

    memset(key, 0, 32);
    memset(iv, 0, 16);

    return rc;
}
