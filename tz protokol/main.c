#include "func.h"

int main(int argc, char *argv[]) {
	if (argc == 1) {
	printf("Incorrect input\n");
        help();
                return 1;	
	}
	if (argc < 5 && (strcmp(argv[1], "-l") != 0 && strcmp(argv[1], "--help") != 0)) {
        printf("Incorrect input\n");
	help();
		return 1;
	}   
	static struct option long_options[] = { 
                    {"pass", required_argument, 0, 'p'},
                    {"input", required_argument, 0, 'i'},
                    {"output", required_argument, 0, 'o'},
                    {"hmac", required_argument, 0, 'h'},
                    {"enc", no_argument, 0, 'e'},
                    {"dec", no_argument, 0, 'd'}, 
                    {"iv", required_argument, 0, 'v'},
                    {"alg", required_argument, 0, 'a'},
                    {"nonce", required_argument, 0, 'n'},
		    {"help", no_argument, 0, 'l'},
                    {0, 0, 0, 0}};
	char *input_path = NULL, *output_path = NULL, *hash = NULL, *cipher = NULL, code[3];
	unsigned char enc, type_c = 0x1, type_h = 0x1, *opentext = NULL, *ciphtext = NULL, *nonce = NULL, *iv = NULL, *iv1 = NULL, *password = calloc(4, 1), *key = NULL;
	int len_key = 16, len = 0, block_size = 16, opt = 0, long_index = 0, arguments = 0;
	FILE *inp, *out;
	srand(time(NULL));
	while ((opt = getopt_long(argc, argv, ":p:i:o:h:edv:a:n:l", long_options, &long_index)) != -1) {
                    switch (opt) {
		    case 'l': help();
			   my_free(iv), my_free(nonce), my_free(hash), free(password), my_free(cipher);
			    return 0;
                    case 'e': enc = 1, ++arguments;
                            break;
		    case 'd': enc = 0, ++arguments;
			    break;
                    case 'p': ASCII_to_hhx(optarg, password), ++arguments;
                            break;
                    case 'i': input_path = optarg, ++arguments;
                            break;
                    case 'o': output_path = optarg, ++arguments;
                            break;
                    case 'h': hash = (char *) calloc(4, 1);
				memcpy(hash, optarg, strlen(optarg));
                            break;
                    case 'a': cipher = (char *) calloc(6, 1);
				memcpy(cipher, optarg, strlen(optarg));
                            break;
                    case 'n': nonce = calloc(64, 1);
				ASCII_to_hhx(optarg, nonce);
                            break;
                    case 'v': iv = calloc(strlen(optarg), 1);
				ASCII_to_hhx(optarg, iv);
                            break;
                    case ':': printf("Error, enter quantity for argument\n");
                            my_free(iv), my_free(nonce), my_free(hash), free(password), my_free(cipher);
                            return 1;
                    default: printf("Error, too many argument, please repeat\n");
                            my_free(iv), my_free(nonce), my_free(hash), free(password), my_free(cipher);
                            return 1;
                    }
            }
	if (arguments != 4 || (enc == 0 && (nonce != NULL || iv != NULL || hash != NULL || cipher != NULL))) {
		printf("Error, incorrect input\n");
		help();
		my_free(iv), my_free(nonce), my_free(hash), free(password), my_free(cipher);
		return 1;
	}
	if (enc == 1) {
		if (cipher == NULL) {
			cipher = (char *) calloc(6, 1);
			memcpy(cipher, "aes128", 6);
		}
		if (hash == NULL) {
			hash = (char *) calloc(4, 1);
			memcpy(hash, "sha1", 4);
		}
		len_key = len_find(cipher, hash, &type_c, &type_h, &block_size);
		if (nonce == NULL) {
                        nonce = calloc(64, 1);
			gen_text(nonce, 64); 
                }
		if (iv == NULL) {
                        iv = calloc(block_size, 1);
                	gen_text(iv, block_size);
		}
		key = calloc(len_key, 1);
		iv1 = calloc(block_size, 1);
		memcpy(iv1, iv, block_size);
		create_key(password, nonce, len_key, hash, key);
		
		if ((inp = fopen(input_path, "r")) == NULL) {
			printf("Error, file don`t exist\n");
			my_free(iv1), free(iv), my_free(nonce), free(hash), free(password), free(cipher), my_free(key);
		return 2;
		}
		opentext = calloc(block_size, 1);
		while(!feof(inp)) {
			fread(opentext + len, block_size, 1, inp);
			len += block_size;
			opentext = (unsigned char *) realloc(opentext, len + block_size);	
		}
		fclose(inp);
		ciphtext = calloc(len, 1);
		encrypt_text(opentext, len, iv, key, type_c, ciphtext);
		out = fopen(output_path, "wb");
		fprintf(out, "ENC%c%c", type_h, type_c);
        	fwrite(nonce, sizeof(unsigned char), 64, out); 
        	fwrite(iv1, sizeof(unsigned char), block_size, out); 
        	fwrite(ciphtext, sizeof(unsigned char), len, out); 
		fclose(out);	
	}
	else {
		if ((inp = fopen(input_path, "rb")) == NULL) {
			printf("Error, file don`t exist\n");
                        free(password);
                	return 2;
		}
		fscanf(inp, "%c%c%c%c%c", code, code + 1, code + 2, &type_h, &type_c);
		if (!check(code, type_h, type_c)) {
			printf("Error, invalid file\n");
			fclose(inp);
			free(password);
			return 2;
		}
		cipher = (char *) calloc(6, 1);
		hash = (char *) calloc(4, 1);
		len_key = def_len(type_h, type_c, hash, cipher, &block_size);
		nonce = calloc(64, 1);
		iv = calloc(block_size, 1);
		key = calloc(len_key, 1);
		ciphtext = calloc(block_size, 1);
		fread(nonce, 64, 1, inp);
		fread(iv, block_size, 1, inp);
		while(!feof(inp)) {
                	fread(ciphtext + len, block_size, 1, inp); 
                	len += block_size;
                	ciphtext = (unsigned char *) realloc(ciphtext, len + block_size); 
        	}
		fclose(inp);
		opentext = (unsigned char *) calloc(len, 1);
		create_key(password, nonce, len_key, hash, key);
		decrypt_text(ciphtext, len, iv, key, type_c, opentext);
		out = fopen(output_path, "w+");
		fprintf(out, "%s", opentext);
		fclose(out);
	}
	
	my_free(iv1), free(iv), my_free(opentext), my_free(ciphtext), my_free(nonce), free(hash), free(password), free(cipher), free(key);	
	return 0;
}
