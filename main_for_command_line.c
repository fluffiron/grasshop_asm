/* 
	 This is an implementation of GOST_R_3412-2015 and part of GOST_R_3413-2015 (electronic codebook).
	 C and inline assembler languages were used.
	 Visual Studio was used.
 */
/*
	The code was created just to have fun and learn more about Intel SIMD extensions.
	That's why the majority of operations implemented using inline assembler.
*/
#include "kuznechik.h"
#include"electronic_codebook.h"
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char *argv[])
{
	int i = 0;
	FILE* input = NULL;
	FILE* output = NULL;
	FILE* master_key_sourse = NULL;
	long len_input = 0;
	int len_master_key = 0;
	unsigned char master_key[32] = {0};
	unsigned char* buffer = NULL;

	// Checking passed parameters and input files
	if(argc < 4) {
		printf("Enter: ...exe path_text path_result path_master_key \n");
		// system("pause");
		return 1;
	}
	if(!(input = fopen(argv[1], "rb"))) {
		printf("Can't open input file\n");
#ifdef DEBUG
		system("pause");
#endif
		return 2;
	} else if(!(output = fopen(argv[2], "wb"))) {
		printf("Can't create output file\n");
		fclose(input);
#ifdef DEBUG
		system("pause");
#endif
		return 3;
	} else if(!(master_key_sourse = fopen(argv[3], "rb"))) {
		printf("Can't open master_key file\n");
		fclose(input);
		fclose(output);
#ifdef DEBUG
		system("pause");
#endif
		return 4;
	}

	fseek(master_key_sourse, 0, SEEK_END);
	len_master_key = ftell(master_key_sourse);
	fseek(master_key_sourse, 0, SEEK_SET);

	if(len_master_key != 32) {
		fclose(input);
		fclose(output);
		fclose(master_key_sourse);
		printf("Master_key is not incorrect!\n");
#ifdef DEBUG
		system("pause");
#endif
		return 6;
	}

	fseek(input, 0, SEEK_END);
	len_input = ftell(input);
	fseek(input, 0, SEEK_SET);

	if( len_input % 16 != 0) {
		printf("Can't process data...!\n");
		fclose(input);
		fclose(output);
		fclose(master_key_sourse);
#ifdef DEBUG
		system("pause");
#endif
		return 9;
	}

	buffer = (unsigned char*)calloc(len_input, sizeof(unsigned char));
	if(!buffer) {
		fclose(input);
		fclose(output);
		fclose(master_key_sourse);
		printf("Can't find buffer!\n");
#ifdef DEBUG
		system("pause");
#endif
		return 5;
	}
	fread(buffer, sizeof(unsigned char), len_input, input);
	
	fread(master_key, sizeof(unsigned char), 32, master_key_sourse);
	if(argv[4][0] == '1') {
	ecodebook_crypt(buffer, master_key, len_input);
	} else if(argv[4][0] == '2') {
	ecodebook_decrypt(buffer, master_key, len_input);
	}
	
	fwrite(buffer, sizeof(char), len_input, output);

	fclose(input);
	fclose(output);
	fclose(master_key_sourse);
	free(buffer);
	printf("Done!\n");
#ifdef DEBUG
	system("pause");
#endif
	return 0;
}