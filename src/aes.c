/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto

  this is public domain code.

  Saju Pillai (saju.pillai@gmail.com)
**/

#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <ccoin/util.h>
#include <ccoin/cstr.h>
#include <ccoin/aes_util.h>

cstring *read_aes_file(const char *filename, void *key, size_t key_len,
		       size_t max_file_len)
{
	void *ciphertext = NULL;
	size_t ct_len = 0;

	if (!bu_read_file(filename, &ciphertext, &ct_len, max_file_len)) {
		return NULL;
	}

	cstring *rs = decrypt_aes_buffer(ciphertext, ct_len, key, key_len);
	if (!rs) {
		free(ciphertext);
	}

	return rs;
}

bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len)
{
	size_t ct_len;
	void *ciphertext =
		encrypt_aes_buffer(plaintext, pt_len, key, key_len, &ct_len);
	if (!ciphertext) {
		return false;
	}

	bool rc = bu_write_file(filename, ciphertext, ct_len);

	free(ciphertext);

	return rc;
}

#if 0
int main(int argc, char **argv)
{
	/* "opaque" encryption, decryption ctx structures that libcrypto uses to record
	   status of enc/dec operations */
	EVP_CIPHER_CTX en, de;

	/* 8 bytes to salt the key_data during key generation. This is an example of
	   compiled in salt. We just read the bit pattern created by these two 4 byte
	   integers on the stack as 64 bits of contigous salt material -
	   ofcourse this only works if sizeof(int) >= 4 */
	unsigned int salt[] = { 12345U, 54321U };
	unsigned char *key_data;
	int key_data_len, i;
	char *input[] =
	    { "a", "abcd", "this is a test", "this is a bigger test",
		"\nWho are you ?\nI am the 'Doctor'.\n'Doctor' who ?\nPrecisely!",
		NULL
	};

	/* the key_data is read from the argument list */
	key_data = (unsigned char *) argv[1];
	key_data_len = strlen(argv[1]);

	/* gen key and iv. init the cipher ctx object */
	if (aes_init
	    (key_data, key_data_len, (unsigned char *) &salt, &en, &de)) {
		printf("Couldn't initialize AES cipher\n");
		return -1;
	}

	/* encrypt and decrypt each input string and compare with the original */
	for (i = 0; input[i]; i++) {
		char *plaintext;
		unsigned char *ciphertext;
		int olen, len;

		/* The enc/dec functions deal with binary data and not C strings. strlen() will
		   return length of the string without counting the '\0' string marker. We always
		   pass in the marker byte to the encrypt/decrypt functions so that after decryption
		   we end up with a legal C string */
		olen = len = strlen(input[i]) + 1;

		ciphertext =
		    aes_encrypt(&en, (unsigned char *) input[i], &len);
		plaintext = (char *) aes_decrypt(&de, ciphertext, &len);

		if (strncmp(plaintext, input[i], olen))
			printf("FAIL: enc/dec failed for \"%s\"\n",
			       input[i]);
		else
			printf("OK: enc/dec ok for \"%s\"\n", plaintext);

		free(ciphertext);
		free(plaintext);
	}

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	return 0;
}
#endif
