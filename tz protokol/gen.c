#include "func.h"
int main(int argc, char *argv[]) {
	if (argc != 4) {
		printf("Error, check your argument\nExample: ./gen 0a0b0cff md5 3des\n");
		return 1;
	}
	srand(time(NULL));
	char *hash = argv[2], *cipher = argv[3];
	char *passw = argv[1], end[] = ".enc";
	int txt_len, size_block = 16;
	unsigned char *opentext;
	if (cipher[0] == '3') {
		size_block = 8;
		txt_len = 64;
		opentext = calloc(txt_len, 1);	
	}
	else {
		txt_len = 64;
		opentext = calloc(txt_len, 1);
	}
	memcpy(opentext + 8, "You have successfully decrypted this text", 42);
	unsigned char *nonce = calloc(64, 1), *iv, *iv1, *password = calloc(4, 1), *key, type_c, type_h;
	int len = len_find(cipher, hash, &type_c, &type_h);
	iv = calloc(size_block, 1);
	iv1 = calloc(size_block, 1);
	key = calloc(len, 1);
	unsigned char *c_text = calloc(txt_len, 1);	
	password = ASCII_to_hhx(passw, password);
	gen_text(nonce, 64);
	gen_text(iv, size_block);
	memcpy(iv1, iv, size_block);
	create_key(password, nonce, len, hash, key);
	encrypt_text(opentext, (size_t) txt_len, iv, key, type_c, c_text);
	
	char *filepath = calloc(strlen(hash) + strlen(cipher) + strlen(passw) + 6 + 1, 1);
	memcpy(filepath, hash, strlen(hash));
	filepath[strlen(hash)] = '_';
	memcpy(filepath + strlen(hash) + 1, cipher, strlen(cipher));
	filepath[strlen(hash) + 1 + strlen(cipher)] = '_';
	memcpy(filepath + strlen(hash) + 1 + strlen(cipher) + 1, passw, 8);
	memcpy(filepath + strlen(hash) + 1 + strlen(cipher) + 1 + 8, end, 4);
	
	FILE *f = fopen(filepath, "wb");
	fprintf(f, "ENC%c%c", type_h, type_c);
	fwrite(nonce, sizeof(unsigned char), 64, f);
	fwrite(iv1, sizeof(unsigned char), size_block, f);
	fwrite(c_text, sizeof(unsigned char), txt_len, f);
	fclose(f);
	free(password), free(nonce), free(iv), free(key), free(filepath), free(c_text), free(opentext), free(iv1);
	return 0;
}
