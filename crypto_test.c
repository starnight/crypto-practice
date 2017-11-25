#include <stdio.h>
#include <stdint.h>
#include <openssl/cmac.h>
#ifdef _EVP_AES_MODE_
#include <openssl/evp.h>
#include <openssl/err.h>
#else 
#include <openssl/aes.h>
#endif

void print_bytes(uint8_t *buf, int len)
{
	int i;

	for(i=0; i<len; i++)
		printf("%02X ", buf[i]);
	printf("\n");
}

int aes_cmac(uint8_t *key, size_t key_sz, void *data, size_t len, void *cmac, size_t *m_len)
{
	CMAC_CTX *ctx;

	ctx = CMAC_CTX_new();
	CMAC_Init(ctx, key, key_sz, EVP_aes_128_cbc(), NULL);
	CMAC_Update(ctx, data, len);
	CMAC_Final(ctx, cmac, m_len);

	CMAC_CTX_free(ctx);

	return 0;
}

#ifdef _EVP_AES_MODE_
uint8_t iv[16] = {0};

void handle_errors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}
#else
void handle_errors(void) {}
#endif

int aes_encrypt(uint8_t *key, size_t key_sz, void *plain, size_t len, void *cipher)
{
#ifdef _EVP_AES_MODE_
	EVP_CIPHER_CTX *ctx;
	int c_l;
	int l;

	ctx = EVP_CIPHER_CTX_new();
	if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handle_errors();
	if (!EVP_EncryptUpdate(ctx, cipher, &l, plain, len))
		handle_errors();
	c_l = l;
	if (!EVP_EncryptFinal_ex(ctx, cipher + c_l, &l))
		handle_errors();
	c_l += l;
	printf("Cipher length: %d bytes\n", c_l);
	EVP_CIPHER_CTX_free(ctx);

	return c_l;
#else
	int ret;
	int bits;
	AES_KEY enc_key;
	int i, b;
	void *src;
	void *dst;

	bits = key_sz * 8;
	ret = AES_set_encrypt_key(key, bits, &enc_key);

	printf("ret = %d, %ld\n", ret, (len/key_sz + 1));
	if (ret == 0) {
		b = (len % key_sz) ? (len/key_sz) + 1 : (len/key_sz);
		for (i = 0; i < b; i++) {
			src = plain + i * key_sz;
			dst = cipher + i * key_sz;
			AES_encrypt(src, dst, &enc_key);
		}
		ret = len;
	}

	return ret;
#endif
}

int aes_decrypt(uint8_t *key, size_t key_sz, void *cipher, size_t len, void *plain)
{
#ifdef _EVP_AES_MODE_
	EVP_CIPHER_CTX *ctx;
	int p_l;
	int l;

	ctx = EVP_CIPHER_CTX_new();
	if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		handle_errors();
	if (!EVP_DecryptUpdate(ctx, plain, &l, cipher, len))
		handle_errors();
	p_l = l;
	if (!EVP_DecryptFinal_ex(ctx, plain + p_l, &l))
		handle_errors();
	p_l += l;
	printf("Plain length: %d bytes\n", p_l);
	EVP_CIPHER_CTX_free(ctx);

	return p_l;
#else
	int ret;
	int bits;
	AES_KEY dec_key;
	int i, b;
	void *src;
	void *dst;

	bits = key_sz * 8;
	ret = AES_set_decrypt_key(key, bits, &dec_key);

	printf("ret = %d\n", ret);
	if (ret == 0) {
		b = (len % key_sz) ? (len/key_sz) + 1 : (len/key_sz);
		for (i = 0; i < b; i++) {
			src = cipher + i * key_sz;
			dst = plain + i * key_sz;
			AES_decrypt(src, dst, &dec_key);
		}
		ret = len;
	}

	return ret;
#endif
}

int main(void)
{
	uint8_t key[] = { 0x2b,0x7e,0x15,0x16, 
			  0x28,0xae,0xd2,0xa6,
			  0xab,0xf7,0x15,0x88,
			  0x09,0xcf,0x4f,0x3c};
	size_t key_sz = sizeof(key);
	uint8_t msg[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	uint8_t enc_data[128] = {0};
	int enc_len;
	uint8_t dec_data[128] = {0};
	int dec_len;
	uint8_t mact[20] = {0};
	size_t mact_len;
	
	aes_cmac(key, key_sz, msg, sizeof(msg), mact, &mact_len);
	printf("Origianl msg:\n");
	print_bytes(msg, sizeof(msg));
	printf("CMAC:\n");
	print_bytes(mact, mact_len);

	enc_len = aes_encrypt(key, key_sz, msg, sizeof(msg), enc_data);
	printf("Origianl msg:\n");
	print_bytes(msg, sizeof(msg));
	printf("Encrypted msg:\n");
	print_bytes(enc_data, enc_len);

	dec_len = aes_decrypt(key, key_sz, enc_data, enc_len, dec_data);
	printf("Encrypted msg:\n");
	print_bytes(enc_data, enc_len);
	printf("Decrypted msg:\n");
	print_bytes(dec_data, dec_len);

	return 0;
}
