#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#define short_options "vm:edk:i:gh"
const struct option long_options[] = {
		{"version", no_argument, NULL, 'v'},
		{"mod", required_argument, NULL, 'm'},
		{"enc", no_argument, NULL, 'e'},
		{"dec", no_argument, NULL, 'd'},
		{"key", required_argument, NULL, 'k'},
		{"iv", required_argument, NULL, 'v'},
		{"debug", no_argument, NULL, 'g'},
		{"help", no_argument, NULL, 'h'},
		{NULL, 0, NULL, 0}
	};
unsigned int key = 0;
int mode = -1;
int shifr_deshifr = -1;
int debug = 0;
unsigned int iv = -1;
unsigned int iv1 = -1;
char* a;
int lenght;
int n = 0;
int j;

unsigned int aes[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,0x2b, 0xfe, 0xd7, 0xab, 0x76,0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,0x51, 0xa3, 0x40, 0x9f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

void input (int argc, char *argv[], int option_index);
unsigned int in_int(char *a);
int check_str(char* s, char*s1);
void generating_keys(unsigned int*  k1);
unsigned int inverting(unsigned int k);
void check_key(unsigned int* k);
int str(FILE * p);
void function_first (unsigned int * C0, FILE *p, unsigned int  key1, unsigned int key2);
int function_second (unsigned int * C0, FILE *p, unsigned int  key1, unsigned int key2);
void debug_ (unsigned int *a1, unsigned int  a);
void information_block(unsigned int *C, FILE *p);
unsigned int check_num(unsigned int a);
void s_blok (unsigned int *c, unsigned int k);
void s_blok1 (unsigned int *c, unsigned int k );
void print(unsigned int *c, unsigned int key1, unsigned int key2);
void vector_iv(unsigned int *c);
void vector_key(unsigned int *c);

void input (int argc, char *argv[], int option_index){  
	int rez=getopt_long(argc, argv, short_options, long_options, NULL);
	while ((rez)!=-1){
		switch(rez){  
			case 'h' :{
					printf("option that you can use :\n");
					printf("'m'- you can choose ecb or cbc\n");
					printf("'e' or 'd'- you can choose encryption or decryption\n");
					printf("'k'- you can write key in hex\n");
					printf("'i'- you can write vector in hex \n");
					printf("'g'- debug \n");
					printf("'t'- u can chek time work \n");
					printf("for example :./cipher -m ecb -e -k ffffffff filename > outname \n");
					printf("you mast write filename and outname at the end of the command  \n");
					break;
				}
			case 'k': {
				key = in_int(optarg);
				break;
			};
			case 'm': {
				if (check_str("ecb",optarg)){
					mode=0;
					break;
				}	
				if (check_str("cbc",optarg)){
					mode=1;
					break;
				}
				if(mode==-1)
					printf(" you write '-m',mabe you mean 'ecb' or 'cbc','ofb'?");
				break;
			};
			case 'e':  {
				shifr_deshifr = 0;
				break;
			};
			case 'd':  {
				shifr_deshifr = 1;
				break;
			};
			case 'i':  {
				iv = in_int(optarg);
				break;
			};
			case 'g':  {
				debug = 1;
				break;
			};
			case '?':  {
				printf("found unknown option\n");
				break;
			};
		}
		rez=getopt_long(argc,argv,short_options,long_options,NULL);
	}
 }
 
unsigned int in_int(char *a){
	unsigned int res = 0;
	unsigned int k = 1;
	char *s = (char*)malloc(1*sizeof(int));
	int i = 0, j = 0;
	int lenght = strlen(a);
	for(i = lenght-1; i>=0; i--){
		if(i != lenght-1)
			 k = k*16;
		if((a[i] == 'f') || (a[i] == 'F'))
			res = res+k*15;
		else
		if ((a[i] == 'e') || (a[i] == 'E'))
		 	res = res+k*14;
		else
		if ((a[i] == 'd') || (a[i] == 'D'))
		 	res = res+k*13;
		else
		if ((a[i] == 'c') || (a[i] == 'C'))
		 	res = res+k*12;
		else
		if ((a[i] == 'b') || (a[i] == 'B'))
		 	res = res+k*11;
		else
		if ((a[i] == 'a') || (a[i] == 'A'))
		 	res = res+k*10;
		else
		{	
			s[0] = a[i];
			j = atoi(s);
			res = res+j*k;
		}
	}
	free(s);
	return res;
};

int check_str(char* s,char*s1){
 	int j = 0;
	for(int i = 0; i < 4; i++)
 		if(s[i] == s1[i])
			j++;
	if (j == 4)
		return 1;
	else
		return 0;
}

void generating_keys(unsigned int*  k1){
	*k1 = inverting(key);
	*k1 = *k1^key;
}

unsigned int inverting(unsigned int k){
 	unsigned int res = 0;
	while (k >= 1){  
	 	if (k%2 == 0)
	 		res = res<<1;
	 	else{
	 		res = res<<1;
	 		res = res|1;
	 	}
	 	k/=2;
	}
	return res;
}

void check_key(unsigned int* k){
	int n = 0;
	unsigned int l = *k;
	
	while (*k >= 1){  
	 	*k/=2;
	 	n++;
	}
	*k = l;
	if (n<28)	
		*k = *k<<(32-n);
}

int str(FILE * p){
	int i = 0;
	*(a+i) = fgetc(p);
	while (*(a+i) != EOF){	
		 if (*(a+i) != '\n'){
		 	i++;
		 	a = (char*)realloc(a, (i+1) * sizeof(int));
			*(a+i) = fgetc(p);
		}
		else  
			*(a+i) = fgetc(p);
	}
	return i;
}

void function_first (unsigned int * C0,FILE *p,unsigned int  key1,unsigned int key2){ 

	if (shifr_deshifr == 0){
		if (debug == 1)
			debug_ (C0,key);
		information_block(C0,p);
		s_blok(C0,key);
		s_blok(C0,key1);
		s_blok(C0,key2);
		print(C0,key1,key2);
	}
	else
	if (shifr_deshifr == 1){
		information_block(C0,p);
		s_blok1(C0,key2);
		s_blok1(C0,key1);
		s_blok1(C0,key);
		vector_key(C0);
		print(C0,key1,key2);
		}
	else {
		printf ("program can not work if don t know u want encryption or decryption\n");
		printf ("u can use -help\n");
	}	
}

int function_second (unsigned int * C0,FILE *p,unsigned int  key1,unsigned int key2){
	
	if (shifr_deshifr == 0){		
		information_block(C0,p);
		vector_iv(C0);
		s_blok(C0,key);
		s_blok(C0,key1);
		s_blok(C0,key2);
		print(C0,key1,key2);
		iv = *(C0+0);
	}
	else
	if (shifr_deshifr == 1){
		information_block(C0,p);
		iv1 = *(C0+0);
		s_blok1(C0,key2);
		s_blok1(C0,key1);
		s_blok1(C0,key);
		vector_iv(C0);
		print(C0,key1,key2);
		iv = iv1;
	}
	else 
	{
		printf ("program can not work if don t know u want encryption or decryption\n");
		printf ("u can use -help\n");
	}
	return 0;
}

void debug_ (unsigned int *a1,unsigned int  a){
	 printf("%x^%x\n",*a1,a);
}

void information_block(unsigned int *C, FILE *p){ 
	char *a1 = malloc(8*sizeof(int));
	unsigned int p1;
	unsigned int c1;
	int  i = 0;
	j = n;
	while(i<8){
	 	*(a1+i) = *(a+j);
		i++;
		j++;
	 	if (j >= lenght){
	 	 	while(i < 8){ 	
		 		*(a1+i) = '0';
		 		i++;
		 	}
		 	break;
		 }
	}
	n+=8;
	p1 = in_int(a1);
	if (shifr_deshifr == 0)
		c1 = check_num(p1);
	else  
		c1 = p1;
	if ((shifr_deshifr == 0) && (mode == 0))
		c1 = c1^key;
	C[0] = c1;
}

unsigned int check_num(unsigned int a){
	int n = 0;
	unsigned int l = a;
	while (a >= 1)
	{  
	 	a/=2;
	 	n++;
	}
	if(n < 28)	
		a = l<<(32-n);
	else
		a = l;
	return a;
}

void s_blok (unsigned int *c,unsigned int k){	
       unsigned int l = *(c+0);
       unsigned int *a = malloc(4*sizeof(int));
       int i = 3;
       while(l >= 1){
	       *(a+i) = l%256;
	       l/=256;
	       i--;
       }
	for(i=0;i<4;i++){	
		*(a+i)=aes[(a[i])];
	}
	unsigned int t = *(a+2);
	*(a+2) = *(a+3);
	*(a+3) = t;
	t = 1;
	i = 3;
	l = 0;
	while(i >= 0){
		l = l+*(a+i)*t;
	        t *= 256;
	        i--;
       }	
	*(c+0) = k^l;
}

void s_blok1(unsigned int *c,unsigned int k ){	
       unsigned int l = *(c+0)^k;
       unsigned int *a = malloc(4*sizeof(int));
       int i = 3;
       while(l >= 1){
	       *(a+i) = l%256;
	       l /= 256;
	       i--;
       }
       unsigned int t = *(a+2);
	*(a+2) = *(a+3);
	*(a+3) = t;
	t = 1;
	for(i = 0; i < 4; i++)
	{	for (int j = 0; j < 256; j++ )
		 if (*(a+i) == aes[j]){
		  	*(a+i)=j;
		  	break;
		 }
	}
	i = 3;
	l = 0;
	while(i >= 0){
		l = l+*(a+i)*t;
	        t *= 256;
	        i--;
       }	
	*(c+0) = l;
}

void print(unsigned int *c,unsigned int key1,unsigned int key2){
	printf("%08X",*(c+0));
}

void vector_iv(unsigned int *c){	
	*(c+0) = *(c+0)^iv;
}

void vector_key(unsigned int *c){	
	*(c+0) = *(c+0)^key;
}

int main (int argc, char *argv[]){
	unsigned int * key2 = malloc(1*sizeof(int));
	unsigned int * key1 = malloc(1*sizeof(int));
	input (argc,argv,0);
	generating_keys(key2);
	check_key(key2);
	*key1 = inverting(key);
	check_key(key1);
	check_key(&key);
	FILE *p = fopen(argv[argc-1], "r");
	if(!p){
	 	printf("program don t faund file");	
	 	printf ("u can use -help\n");
  		return 0;
	 }
	else{	
		unsigned int * C0 = malloc(1*sizeof(int));
		a = malloc(1*sizeof(int)) ;
		lenght = str(p);
		int l = lenght;
		if (l == 0){
			printf("file haven t word ");
			printf ("u can use -help\n");
		}
		j = 0;
		if (mode == 0){
		 	while (l > 0){
		 	 	function_first (C0,p,*key1,*key2);
		 		l -= 8;
			}
		}
		else{ 
			if (iv == 0){
				printf("%x\n",iv);
				printf("u must write vector in hex if u want cbc");
				return 0;
			}
			if (mode == 1){
				while (l > 0){       
					function_second(C0,p,*key1,*key2);
			 		l -= 8;
			 	}
			}
			else{
				printf ("program can not work if don t know u want ecb or cbc\n");
				printf ("u can use -help\n");
			}
		}	
	}
	printf("\n");
	return 0;
}
