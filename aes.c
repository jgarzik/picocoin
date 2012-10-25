/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto

  this is public domain code. 

  Saju Pillai (saju.pillai@gmail.com)
**/

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <glib.h>

/**
 * Create an 256 bit key and IV using the supplied key_data. salt can be added for taste.
 * Fills in the encryption and decryption ctx objects and returns 0 on success
 **/
static bool aes_init(unsigned char *key_data, int key_data_len,
	     unsigned char *salt, EVP_CIPHER_CTX * e_ctx,
	     EVP_CIPHER_CTX * d_ctx)
{
	int i, nrounds = 1721;
	unsigned char key[32], iv[32];

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha512(), salt, key_data,
			   key_data_len, nrounds, key, iv);
	if (i != 32) {
		printf("Key size is %d bits - should be 256 bits\n", i);
		return false;
	}

	EVP_CIPHER_CTX_init(e_ctx);
	EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
	EVP_CIPHER_CTX_init(d_ctx);
	EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return true;
}

/*
 * Encrypt *len bytes of data
 * All data going in & out is considered binary (unsigned char[])
 */
static unsigned char *aes_encrypt(EVP_CIPHER_CTX * e, const unsigned char *plaintext,
			   size_t *len)
{
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	 *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext + c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

/*
 * Decrypt *len bytes of ciphertext
 */
static unsigned char *aes_decrypt(EVP_CIPHER_CTX * e, const unsigned char *ciphertext,
			   size_t *len)
{
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len + AES_BLOCK_SIZE);

	EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
	EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len);
	EVP_DecryptFinal_ex(e, plaintext + p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}

static bool read_file(const char *filename, void **data_, size_t *data_len_,
		      size_t max_file_len)
{
	void *data;
	struct stat st;

	*data_ = NULL;
	*data_len_ = 0;

	int fd = open(filename, O_RDONLY);
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

static bool write_file(const char *filename, const void *data, size_t data_len)
{
	char *tmpfn = calloc(1, strlen(filename) + 16);
	strcpy(tmpfn, filename);
	strcat(tmpfn, ".XXXXXX");

	int fd = mkstemp(tmpfn);
	if (fd < 0)
		goto err_out_tmpfn;

	ssize_t wrc = write(fd, data, data_len);
	if (wrc != data_len)
		goto err_out_fd;

	close(fd);
	fd = -1;

	if (rename(tmpfn, filename) < 0)
		goto err_out_fd;

	free(tmpfn);
	return true;

err_out_fd:
	if (fd >= 0)
		close(fd);
	unlink(tmpfn);
err_out_tmpfn:
	free(tmpfn);
	return false;
}


GString *read_aes_file(const char *filename, void *key, size_t key_len,
		       size_t max_file_len)
{
	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = { 4185398345, 2729682459 };
	void *ciphertext = NULL;
	size_t ct_len = 0;
	GString *rs = NULL;

	if (!read_file(filename, &ciphertext, &ct_len, max_file_len))
		goto out;

	if (!aes_init(key, key_len, (unsigned char *) &salt, &en, &de))
		goto out;

	size_t pt_len = 0;
	void *plaintext = aes_decrypt(&de, ciphertext, &pt_len);

	rs = g_string_new_len(plaintext, pt_len);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

out:
	free(ciphertext);
	return rs;
}

bool write_aes_file(const char *filename, void *key, size_t key_len,
		    const void *plaintext, size_t pt_len)
{
	EVP_CIPHER_CTX en, de;
	unsigned int salt[] = { 4185398345, 2729682459 };

	if (!aes_init(key, key_len, (unsigned char *) &salt, &en, &de))
		return false;

	size_t ct_len = pt_len;
	void *ciphertext = aes_encrypt(&en, plaintext, &ct_len);

	EVP_CIPHER_CTX_cleanup(&en);
	EVP_CIPHER_CTX_cleanup(&de);

	bool rc = write_file(filename, ciphertext, ct_len);
	
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
	unsigned int salt[] = { 12345, 54321 };
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
