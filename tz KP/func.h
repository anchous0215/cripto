#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/des.h>

int len_find(char *type_c, char *type_h, unsigned char *c, unsigned char *h, int *block_size);
int def_len(unsigned char type_h, unsigned char type_c, char *hash, char *cipher, int *block_size);
int check(char *code, char hash, char cipher);
void my_free(void *pointer);
int compare(unsigned char *s1);
unsigned char *ASCII_to_hhx(char *s, unsigned char *x);
unsigned char *int_to_hhx(unsigned long int in, unsigned char *x);
unsigned char *gen_text(unsigned char *text, size_t len);
unsigned char *hmac_md5(unsigned char *nonce, size_t nonce_len, unsigned char *password, size_t password_len, unsigned char *key);
unsigned char *hmac_sha1(unsigned char *nonce, size_t nonce_len, unsigned char *password, size_t password_len, unsigned char *key);
unsigned char *create_key(unsigned char *password, unsigned char *nonce, size_t key_len, char *type, unsigned char *key);
void des3_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void des3_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void aes128_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void aes128_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void aes192_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void aes192_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void aes256_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void aes256_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out);
void help();
