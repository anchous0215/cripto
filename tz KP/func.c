#include "func.h"


int len_find(char *type_c, char *type_h, unsigned char *c, unsigned char *h, int *block_size) {
	int len = 0;
	if (type_c[0] == '3') {
                len = 24;//
		*c = 0x0;
		*block_size = 8;
	} 
        else if (type_c[3] == '2') {
                len = 32;
		*c = 0x3; 
	}
        else if (type_c[4] == '9') {
                len = 24;
		*c = 0x2; 
	}
        else {
                len = 16;
		*c = 0x1;
	}
	if (type_h[2] == '5')
		*h = 0x0;
	else
		*h = 0x1;
	return len;
}

int def_len(unsigned char type_h, unsigned char type_c, char *hash, char *cipher, int *block_size) {
	int len = 0;
	if (type_h == 0x0)
		memcpy(hash, "md5", 3);
	else
		memcpy(hash, "sha1", 4);
	if (type_c == 0x0) {
		memcpy(cipher, "3des", 4);
		len = 24;//
		*block_size = 8;
	}
	else if (type_c == 0x1) {
		memcpy(cipher, "aes128", 6);
		len = 16;
	}
	else if (type_c == 0x2) {
		memcpy(cipher, "aes192", 6);
		len = 24;
	}
	else {
		memcpy(cipher, "aes256", 6);
		len = 32;
	}
	return len;
}

int check(char *code, char hash, char cipher) {
	if (code[0] == 'E' && code[1] == 'N' && code[2] == 'C' && ((int) hash == 0 || (int) hash== 1) && ((int) cipher >= 0 && (int) cipher <= 3))
		return 1;
	else
		return 0;
}

void my_free(void *pointer) {
	if (pointer != NULL)
		free(pointer);
}

int compare(unsigned char *s1) {
	int res = 0;
	for (int i = 0; i < 8; ++i) {
		if (s1[i] == 0x0)
			++res;
	}
	return (res / 8);
}

unsigned char *ASCII_to_hhx(char *s, unsigned char *x) {
    int len = (int) strlen(s), j = 0;
    for (int i = len - 1; i >= 0; --i) {
        if ((int) s[i] >= '0' && (int) s[i] <= '9') {
            x[((len / 2) - 1) - j] |= ((unsigned char) ((int) s[i] - '0')) << (((i + 1) % 2) * 4); 
        }
        if((int) s[i] >= 'a' && (int) s[i] <= 'f') {
            x[((len / 2) - 1) - j] |= ((unsigned char) ((int) s[i] - ('a' - 10))) << (((i + 1) % 2) * 4);
        }
        if (i % 2 == 0)
            ++j;
    }
    return x;
}

unsigned char *int_to_hhx(unsigned long int in, unsigned char *x) {
	for (int i = 0; i < 4; ++i) {
		x[i] = ((in >> ((3 - i) * 8)) & 0xff);
	}
	return x;
}

unsigned char *gen_text(unsigned char *text, size_t len) {
    unsigned char text1[len];

    if (text == NULL)
        text = text1;

    for (int i = 0; i < len; ++i) {
        text[i] = (unsigned char) (rand() % 256);
    }
    return text;
}


unsigned char *hmac_md5(unsigned char *nonce, size_t nonce_len, unsigned char *password, size_t password_len, unsigned char *key) {
	unsigned char key1[16];
	MD5_CTX context;
	unsigned char k_ipad[64], k_opad[64];
	
	if (key == NULL)
		key = key1;

	memset(k_ipad, 0x36, sizeof(k_ipad));
	memset(k_opad, 0x5c, sizeof(k_opad));
	
	for(int i = 0; i < password_len; ++i) {
		k_ipad[i] ^= password[i];
		k_opad[i] ^= password[i];
	}

	MD5_Init(&context);
	MD5_Update(&context, k_ipad, 64);
	MD5_Update(&context, nonce, nonce_len);
	MD5_Final(key, &context);

	MD5_Init(&context);
        MD5_Update(&context, k_opad, 64);
        MD5_Update(&context, key, 16);
        MD5_Final(key, &context);

	return key;
}

unsigned char *hmac_sha1(unsigned char *nonce, size_t nonce_len, unsigned char *password, size_t password_len, unsigned char *key) {
        unsigned char key1[20];
        SHA_CTX context;
        unsigned char k_ipad[64], k_opad[64];
     
        if (key == NULL)
                key = key1;

        memset(k_ipad, 0x36, sizeof(k_ipad));
        memset(k_opad, 0x5c, sizeof(k_opad));
     
        for(int i = 0; i < password_len; ++i) {
                k_ipad[i] ^= password[i];
                k_opad[i] ^= password[i];
        }   

        SHA1_Init(&context);
        SHA1_Update(&context, k_ipad, 64);
        SHA1_Update(&context, nonce, nonce_len);
        SHA1_Final(key, &context);

        SHA1_Init(&context);
        SHA1_Update(&context, k_opad, 64);
        SHA1_Update(&context, key, 16);
        SHA1_Final(key, &context);

        return key;
}

unsigned char *create_key(unsigned char *password, unsigned char *nonce, size_t key_len, char *type, unsigned char *key) {
	if (type[2] == '5') {
		unsigned char *hmac1 = calloc(16, 1), *hmac2 = calloc(16, 1);
		hmac_md5(nonce, 64, password, 4, hmac1);
		for (int i = 0; i < 16; ++i)
			key[i] = hmac1[i];
		
		if (key_len > 16) {
			hmac_md5(hmac1, 16, password, 4, hmac2);
			for (int i = 16; i < key_len - 16; ++i)
				key[i] = hmac2[i - 16];
		}
		free(hmac1), free(hmac2);
	}
	else {
		unsigned char *hmac1 = calloc(20, 1), *hmac2 = calloc(20, 1); 
                hmac_sha1(nonce, 64, password, 4, hmac1);
                if (key_len < 20) {
			for (int i = 0; i < key_len; ++i)
				key[i] = hmac1[i];
		}
		else {
			for (int i = 0; i < 20; ++i)
                        	key[i] = hmac1[i];
             
                        hmac_sha1(hmac1, 20, password, 4, hmac2);
                        for (int i = 20; i < key_len; ++i)
                                key[i] = hmac2[i - 20];
                }
		free(hmac1), free(hmac2);
	}
	return key;
}

void des3_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
	DES_cblock key1, key2, key3;
	DES_key_schedule ks1, ks2, ks3;
	
	memcpy(key1, key, 8);
	memcpy(key2, key + 8, 8);
	memcpy(key3, key + 16, 8);
	
	DES_set_key((DES_cblock *) key1, &ks1);
	DES_set_key((DES_cblock *) key2, &ks2);
	DES_set_key((DES_cblock *) key3, &ks3);

	DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_DECRYPT);
}

void des3_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
        DES_cblock key1, key2, key3;
        DES_key_schedule ks1, ks2, ks3;

        memcpy(key1, key, 8);
        memcpy(key2, key + 8, 8);
        memcpy(key3, key + 16, 8);

        DES_set_key((DES_cblock *) key1, &ks1);
        DES_set_key((DES_cblock *) key2, &ks2);
        DES_set_key((DES_cblock *) key3, &ks3);

        DES_ede3_cbc_encrypt(in, out, in_len, &ks1, &ks2, &ks3, (DES_cblock *) iv, DES_ENCRYPT);
}

void aes128_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
	AES_KEY akey;
	AES_set_decrypt_key(key, 128, &akey);
	AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}

void aes128_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
        AES_KEY akey;
        AES_set_encrypt_key(key, 128, &akey);
        AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}

void aes192_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
        AES_KEY akey;
        AES_set_decrypt_key(key, 192, &akey);
        AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}

void aes192_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
        AES_KEY akey;
        AES_set_encrypt_key(key, 192, &akey);
        AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}

void aes256_cbc_decrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
        AES_KEY akey;
        AES_set_decrypt_key(key, 256, &akey);
        AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_DECRYPT);
}

void aes256_cbc_encrypt(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char *out) {
        AES_KEY akey;
        AES_set_encrypt_key(key, 256, &akey);
        AES_cbc_encrypt(in, out, in_len, &akey, iv, AES_ENCRYPT);
}

unsigned char *encrypt_text(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char type_c, unsigned char *cipher_text) { //
	if (type_c == 0x1)
		aes128_cbc_encrypt(in, in_len, iv, key, cipher_text);
	else if (type_c == 0x2)
		aes192_cbc_encrypt(in, in_len, iv, key, cipher_text);
	else if (type_c == 0x3)
		aes256_cbc_encrypt(in, in_len, iv, key, cipher_text);
	else
		des3_cbc_encrypt(in, in_len, iv, key, cipher_text);
	return cipher_text;
}

unsigned char *decrypt_text(unsigned char *in, size_t in_len, unsigned char *iv, unsigned char *key, unsigned char type_c, unsigned char *open_text) { //
        if (type_c == 0x1)
                aes128_cbc_decrypt(in, in_len, iv, key, open_text);
	else if (type_c == 0x2) 
                aes192_cbc_decrypt(in, in_len, iv, key, open_text);
        else if (type_c == 0x3) 
                aes256_cbc_decrypt(in, in_len, iv, key, open_text);
        else
                des3_cbc_decrypt(in, in_len, iv, key, open_text);
        return open_text;
}

void help() {
	printf("Necesary attributes:\n-e (--enc) - encryption or -d (--dec) - decryption\n-p (--pass) - 4th bytes password\n-i (--input) - input filepath\n-o (--output) - output filepath\nAdding attributes:\n-h (--hmac) - hmac function md5/sha1\n-a (--alg) - algoritm of cyphering 3des/as=es128/aes192/aes256\n-n (--nonce) - 16th bytes nonce\n-v (--iv) vector initilization\n-l (--help) help with arguments\nFor example:\n./crypter -e -p 00000000 -i 1.txt -o 1.enc\nor\n./crypter -e -p 00000000 -h md5 -a aes128 --iv 00000000000000000000000000000000 -i 1.txt -o 1.enc\n");
}
