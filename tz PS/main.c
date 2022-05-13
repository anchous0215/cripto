#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

void help();
unsigned char *ASCII_to_hhx(char *s, unsigned char *x);
unsigned char it_reg1(unsigned char *reg);
unsigned char it_reg2(unsigned char *reg);
unsigned char it_reg3(unsigned char *reg);
unsigned char func(unsigned char a, unsigned char b, unsigned char c);
void ciphering(unsigned char *reg1, unsigned char *reg2, unsigned char *reg3, char *filepath);

unsigned char *ASCII_to_hhx(char *s, unsigned char *x) {
    int len = (int) strlen(s), j = 0;
    for (int i = len - 1; i > 0; --i) {
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

unsigned char it_reg1(unsigned char *reg) {
    unsigned char res = reg[0], new = reg[0] ^ reg[2] ^ reg[4] ^ 0x1;
    for(int i = 0; i < 6; ++i)
        reg[i] = reg[i + 1];
    reg[6] = new;

    return res;
}

unsigned char it_reg2(unsigned char *reg) {
    unsigned char res = reg[0], new = reg[2] ^ reg[4] ^ reg[6] ^ 0x1;
    for(int i = 0; i < 8; ++i)
        reg[i] = reg[i + 1];
    reg[8] = new;
    return res;
}

unsigned char it_reg3(unsigned char *reg) {
    unsigned char res = reg[0], new = reg[4] ^ reg[6] ^ reg[8] ^ 0x1;
    for(int i = 0; i < 10; ++i)
        reg[i] = reg[i + 1];
    reg[10] = new;
    return res;
}

unsigned char func(unsigned char a, unsigned char b, unsigned char c) {
    return (unsigned char) (((a*b*c) % 256 + (a*b) % 256 + (a*c) % 256 + 1) % 256);
}

void ciphering(unsigned char *reg1, unsigned char *reg2, unsigned char *reg3, char *filepath) {
    char inp1, inp2;
    unsigned char p, a, b, c;
    FILE *txt; 
    if ((txt = fopen(filepath, "r+")) == NULL) {
        printf("Error, file don`t exist\n");
        return;
    }
    while(fscanf(txt, "%c", &inp1) != EOF && fscanf(txt, "%c", &inp2) != EOF) {
        p = 0x0;
        if ((int) inp1 > 47 && (int) inp1 < 58) {
            p |= ((unsigned char) ((int) inp1 - 48)) << 4;
        }
        else if((int) inp1 > 96 && (int) inp1 < 103) {
            p |= ((unsigned char) ((int) inp1 - 87)) << 4;
        }
        if ((int) inp2 > 47 && (int) inp2 < 58) {
            p |= ((unsigned char) ((int) inp2 - 48));
        }
        else if((int) inp2 > 96 && (int) inp2 < 103) {
            p |= ((unsigned char) ((int) inp2 - 87));
        }
        a = it_reg1(reg1);
        b = it_reg2(reg2);
        c = it_reg3(reg3);
        printf("%02hhx", (unsigned char) (p ^ func(a, b, c)));
    }
    fclose(txt);
    printf("\n");
}

void help() {
    printf("-h, --help: for help with argument;\n-k, --key=[value]: path to the key;\nFor example\n./cipher -k path_to_file_with_key.txt path_to_file_with_ciphertext.txt\nor\n./cipher --key=path_to_file_with_key.txt path_to_file_with_ciphertext.txt\n");
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        printf("Incorrect input\nFor example:\n./cipher -k path_to_file_with_key.txt path_to_file_with_ciphertext.txt\nor\n./cipher --key=path_to_file_with_key.txt path_to_file_with_ciphertext.txt\n");
return 1;
}
    static struct option long_options[] = {
        {"key", required_argument, 0, 'k'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};
    FILE *f; 
    int opt = 0, long_index = 0;
    char key[55], key1[15], key2[19], key3[23], *path = NULL, *key_path = NULL;
    unsigned char *reg1 = calloc(7, sizeof(unsigned char)), *reg2 = calloc(9, sizeof(unsigned char)), *reg3 = calloc(11, sizeof(unsigned char));
    while ((opt = getopt_long(argc, argv, ":hk:", long_options, &long_index)) != -1) {
    	switch (opt) {
    	case 'h': help();
			return 0;
    	case 'k':
		key_path = (char *) calloc(strlen(optarg), sizeof(char));
		key_path = optarg;
		break;
    	case ':': printf("Error, enter quantity for argument\n");
                              return 1;
    	default: printf("Error, too many argument, please repeat\n");
                              return 1;
    	}
    }
    for (; optind < argc; ++optind) {
         path = (char *) calloc(strlen(argv[optind]), sizeof(char));
         path = argv[optind];
    }
    if ((f = fopen(key_path, "r+")) == NULL) {
		printf("Error, file don`t exist\n");
		return 1;
    }
    fscanf(f, "%s", key);
    fclose(f);
    if (strlen(key) < 54) {
        printf("Error incorrect len of key\n");
        return 1;
    }
    for(int i = 0; i < 14; key1[i] = key[i], ++i);
    for(int i = 14; i < 32; key2[i - 14] = key[i], ++i);
    for(int i = 32; i < 54; key3[i - 32] = key[i], ++i);
    key1[14] = '\0', key2[18] = '\0', key3[22] = '\0';
    ASCII_to_hhx(key1, reg1);
    ASCII_to_hhx(key2, reg2);
    ASCII_to_hhx(key3, reg3);
    ciphering(reg1, reg2, reg3, path);
    return 0;
}
