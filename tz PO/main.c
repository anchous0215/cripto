#include "func.h"

int main(int argc, char *argv[]) {
	if (argc > 4) {
		printf("Error, too many arguments\n");
		return 1;
	}
	else if (argc == 1){
		printf("Error, a little arguments\n");
		return 1;
	}
	char *filepath;
	int verbose = 0, parall = 0;
	if (argc == 2) {
		filepath = argv[1];
	}
	else if (argc == 3 && argv[1][1] == 'v'){
		verbose = 1;
		filepath = argv[2];
	}
	else if (argc == 3 && argv[1][1] == 'p') {
		parall = 1;
		filepath = argv[2];
	}
	else {
		verbose = 1;
		parall = 1;
                filepath = argv[3];
	}
	
	char *hash = (char *) calloc(4, 1), *cipher = (char *) calloc(6, 1);
	unsigned char type_h, type_c, *nonce = (unsigned char *) calloc(64, 1), *iv, *iv1, *ct, *key, *opentext, *pass = calloc(4, 1);
	int key_len = 0, len_ct = 0;
	unsigned long int password = 0xffffffff;
	char code[3];
	FILE *f;
	if ((f = fopen(filepath, "rb")) == NULL) {
		printf("Error, file don`t exist\n");
		return 2;
	}
	fscanf(f, "%c%c%c%c%c", code, code + 1, code + 2, &type_h, &type_c);
	key_len = def_len(type_h, type_c, hash, cipher);
	int block_size = 16; 
        if (type_c == 0x0)
                block_size = 8;
	
	iv = (unsigned char *) calloc(block_size, 1);
	iv1 = (unsigned char *) calloc(block_size, 1);
	key = (unsigned char *) calloc(key_len, 1);
	hash = (char *) realloc(hash, strlen(hash));
	cipher = (char *) realloc(cipher, strlen(cipher));

	ct = (unsigned char *) calloc(block_size, 1);
	
	if (check(code, type_h, type_c))
		printf("Valid file\n");
	else {
		printf("Error, invalid file\n");
		return 1;
	}
	printf("hmac_%s, %s\n", hash, cipher);
	fread(nonce, 64, 1, f);
	fread(iv, block_size, 1, f);
	while(!feof(f)) {
		fread(ct + len_ct, block_size, 1, f);
		len_ct += block_size;
		ct = (unsigned char *) realloc(ct, len_ct + block_size);
	}
	fclose(f);
	opentext = (unsigned char *) calloc(len_ct, 1);
	
	printf("nonce: ");
	for (int i = 0; i < 64; ++i)
		printf("%02hhx", nonce[i]);
	printf("\niv: ");
	for (int i = 0; i < block_size; ++i)
		printf("%02hhx", iv[i]);
	printf("\n CT: ");
	for (int i = 0; i < len_ct; ++i)
		printf("%02hhx", ct[i]);
	printf("\n\nStart cracking\n");
	memcpy(iv1, iv, block_size);
	
	pid_t pid;
	
	double total_time = 0, part_time = 0;
        clock_t time = 0, ptime = 0;
        time = clock();
	
	if (parall) {
	pid = fork();
	if (pid == 0) {
	if (verbose == 0) {
		for (unsigned long int i = 0x0; i < 0xffffffff && password == 0xffffffff; i += 2) {
			memcpy(iv, iv1, block_size);
			memset(key, 0x0, key_len);
			memset(opentext, 0x0, len_ct);
			create_key(int_to_hhx(i, pass), nonce, key_len, hash, key);
			decrypt_text(ct, len_ct, iv, key, type_c, opentext);	
			if (compare(opentext))
				password &= i;
		}
	
	}
	else {
		for (unsigned long int i = 0x0; i < 0xffffffff && password == 0xffffffff; i += 2) {
                	if (!(i % 0xffff)) {
				if (i == 0)
					ptime = clock();
				else {
					part_time = (double) (clock() - ptime) / CLOCKS_PER_SEC;
					if (part_time == 0)
						part_time = 1; 
					printf("Current: %08lx - %08lx | Speed: %d c/s\n", i - 0xffff, i, (int)((double) 0xffff / part_time));
					ptime = clock();
				}
			}
			memcpy(iv, iv1, block_size);
			memset(key, 0x0, key_len);
                	memset(opentext, 0x0, len_ct);
                	create_key(int_to_hhx(i, pass), nonce, key_len, hash, key);
                	decrypt_text(ct, len_ct, iv, key, type_c, opentext);
                 	if (compare(opentext))
                        	password &= i;
        	}
        }
	}
	else if (password == 0xffffffff) {
		if (verbose == 0) {
                for (unsigned long int i = 0x1; i < 0xfffffffe && password == 0xffffffff; i += 2) {
                        memcpy(iv, iv1, block_size);
                        memset(key, 0x0, key_len);
                        memset(opentext, 0x0, len_ct);
                        create_key(int_to_hhx(i, pass), nonce, key_len, hash, key);
                        decrypt_text(ct, len_ct, iv, key, type_c, opentext);
                        if (compare(opentext))
                                password &= i;
                }

        }
        else {
                for (unsigned long int i = 0x1; i < 0xfffffffe && password == 0xffffffff; i += 2) {
                        /*if (!(i % 0xffff)) {
                                if (i == 0)
                                        ptime = clock();
                                else {
                                        part_time = (double) (clock() - ptime) / CLOCKS_PER_SEC;
                                        if (part_time == 0)
                                                part_time = 1;
                                        printf("Current: %08lx - %08lx | Speed: %d c/s\n", i - 0xffff, i, (int)((double) 0xffff / part_time));
                                        ptime = clock();
                                }
                        }*/
                        memcpy(iv, iv1, block_size);
                        memset(key, 0x0, key_len);
                        memset(opentext, 0x0, len_ct);
                        create_key(int_to_hhx(i, pass), nonce, key_len, hash, key);
                        decrypt_text(ct, len_ct, iv, key, type_c, opentext);
                        if (compare(opentext))
                                password &= i;
                }
        }
	}
	}
////////////////////////////////
	else {
		if (verbose == 0) {
                for (unsigned long int i = 0x0; i < 0xffffffff && password == 0xffffffff; i += 1) {
                        memcpy(iv, iv1, block_size);
                        memset(key, 0x0, key_len);
                        memset(opentext, 0x0, len_ct);
                        create_key(int_to_hhx(i, pass), nonce, key_len, hash, key);
                        decrypt_text(ct, len_ct, iv, key, type_c, opentext);
                        if (compare(opentext))
                                password &= i;
                }

        }
        else {
                for (unsigned long int i = 0x0; i < 0xffffffff && password == 0xffffffff; i += 1) {
                        if (!(i % 0xffff)) {
                                if (i == 0)
                                        ptime = clock();
                                else {
                                        part_time = (double) (clock() - ptime) / CLOCKS_PER_SEC;
                                        if (part_time == 0)
                                                part_time = 1;
                                        printf("Current: %08lx - %08lx | Speed: %d c/s\n", i - 0xffff, i, (int)((double) 0xffff / part_time));
                                        ptime = clock();
                                }
                        }
                        memcpy(iv, iv1, block_size);
                        memset(key, 0x0, key_len);
                        memset(opentext, 0x0, len_ct);
                        create_key(int_to_hhx(i, pass), nonce, key_len, hash, key);
                        decrypt_text(ct, len_ct, iv, key, type_c, opentext);
                        if (compare(opentext))
                                password &= i;
                }
        }
	}
	
	time = clock() - time;
	total_time = (double) time / CLOCKS_PER_SEC;
	if (total_time == 0)
		total_time = 1;
	printf("Found: %08lx | Speed: %d c/s\n", password, (int) ((double) password / total_time));
	if (parall) {
                if (pid == 0)
                        exit(0);
        
	}		
	free(hash), free(cipher), free(iv1), free(nonce), free(iv), free(ct), free(opentext), free(pass);
	return 0;
}
