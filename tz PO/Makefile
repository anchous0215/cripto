all:
	gcc -g -Wall gen.c func.c -lssl -lcrypto -o gen
	gcc -Wall -g -o verifier verifier.c func.c -lssl -lcrypto
	gcc -g -Wall main.c func.c -lssl -lcrypto -o main
