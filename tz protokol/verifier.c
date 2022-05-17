#include "func.h"

int main(int argc, char *argv[]) {
	if (argc != 2) {
		printf("Error, need enter filepath\n");
		return 1;
	}
	char *filepath = malloc(sizeof(char) * strlen(argv[1]) + 1);
	strcpy(filepath, argv[1]);
	filepath[strlen(argv[1])] = '\0';
	char code[3], hash, cip;
	int j = 0;
	FILE *f;
	if ((f = fopen(filepath, "rb")) == NULL) {
		printf("Error, file don`t exist\n");
		return 1;
	}
	fscanf(f, "%c%c%c", &code[0], &code[1], &code[2]);
	fscanf(f, "%c%c", &hash, &cip);
	while(!feof(f)) {
		fscanf(f, "%*c");
		++j;
	}
	if (check(code, hash, cip) && (filepath[strlen(filepath) - 3] == 'e' && filepath[strlen(filepath) - 2] == 'n' && filepath[strlen(filepath) - 1] == 'c')) {
		if (((int) cip == 0 && (j >= 86 && j <=4181)) || ((int) cip == 1 && (j >= 81 && j <=4176)) || ((int) cip == 2 && (j >= 89 && j <=4184)) || ((int) cip == 3 && (j >= 97 && j <=4192)))
			printf("True\n");
	}
	else
		printf("False\n");
	fclose(f);
	return 0;
}
