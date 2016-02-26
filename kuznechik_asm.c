#include "kuznechik.h"
#include "tables.h"
#include<stdlib.h>
#include <stdio.h>


// Encryption using Kuznechik algorithm
void kuz_encrypt(unsigned char text[16], unsigned char keys[10][16]) {
	int i = 0;
	for(i = 0; i < 9; ++i) {
		LSX(keys[i], text);
	}
	_asm {
		mov esi, text;
		mov edi, keys;
		lea edi, [edi + 16*9];
		movdqu xmm0, [esi];
		movdqu xmm1, [edi];
		pxor xmm0, xmm1;
		movdqu [esi], xmm0;
	}
	return;
}
// Decryption using Kuznechik algorithm
void kuz_decrypt(unsigned char text[16], unsigned char keys[10][16]) {
	int i = 0;
	for(i = 9; i > 0; --i) {
		S_inv_L_inv_X(keys[i], text);
	}
	_asm {
		mov esi, text;
		mov edi, keys;
		lea edi, [edi];
		movdqu xmm0, [esi];
		movdqu xmm1, [edi];
		pxor xmm0, xmm1;
		movdqu [esi], xmm0;
	}
	return;
}
// Generating round keys
void generate_keys(unsigned char keys[10][16], unsigned char* master_key) {
	int i = 1, j = 1;

	_asm {
		mov ecx, 32; // the 1st and the 2nd keys are parts of the master_key
		mov esi, master_key;
		mov edi, [keys];
		rep movsb;
	}
	for(i = 1; i < 5; ++i) {
		int tmp = 0;
		for(tmp = 0; tmp < 16; ++tmp ) {
			keys[2 * i][tmp] = keys[2 * i - 2][tmp];
			keys[2 * i + 1][tmp] = keys[2 * i - 1][tmp];
		}
		for(j = 1; j < 9; ++j) {
			int tmp = 8*(i-1) + j;
			unsigned char k[16] = {0};
			_asm {
				pxor xmm0, xmm0;
				mov eax, tmp;
				pinsrb xmm0, al, 15;
				call L; // in xmm0 there is a result of L()
				lea edi, [k];
				movdqu [edi], xmm0;
			}
			F(k, keys[2 * i], keys[2 * i + 1]);
		}
	}
}

// Function creates lookup table in lookup.h for linear operation over GF(2)[x]/x^8 + x^7 + x^6 + x + 1
void create_lookup_h() {
	unsigned char lookup_table_[16][256] = {0};
	int i = 0, j = 0;
	FILE* lookup = fopen("lookup.h", "w");
	generate_lookup_table(lookup_table_);

	fprintf(lookup, "#ifndef LOOKUP_H\n#define LOOKUP_H\n const unsigned char lookup_table[16][256] = {\n");
	for(i = 0; i < 16; ++i) {
		fprintf(lookup, "{ ");
		for(j = 0; j < 256; ++j) {
			if(j != 255)
				fprintf(lookup, "0x%02x, ", lookup_table_[i][j]);
			else
				fprintf(lookup, "0x%02x", lookup_table_[i][j]);
		}
		if(i != 15)
			fprintf(lookup, "},\n");
		else
			fprintf(lookup, "}\n");
	}
	fprintf(lookup, "};\n\n#endif");
	fclose(lookup);
}

// Create 4kB of lookup table for linear operation l(a15, a14,..., a0)
void generate_lookup_table(unsigned char lookup_table[][256]) {
	int i = 0, j = 0;
	for( i = 0; i < 16; ++i) {
		for( j = 0; j < 256; ++j) {
			lookup_table[i][j] = polynoms_mult(kuz_lvec[i], j);
		}
	}
}

// Fulfill polynomial multiplication
unsigned char polynoms_mult(unsigned char a, unsigned char b) {
	unsigned char product = 0;
	while(b)
	{
		if(b & 1)
		{
			product ^= a;
		}
		a = (a << 1) ^ (a & 0x80 ? 0xC3 : 0x00); // subtract polynomial x^8 + x^7 + x^6 + x + 1
		b >>= 1;
	}
	return product;
}

void LSX(unsigned char* k, unsigned char* a) {

	_asm {
		mov esi, k;
		mov edi, a;
		movdqu xmm2, [esi];
		movdqu xmm0, [edi];
		pxor xmm0, xmm2;
		// movdqu [edi], xmm1;  !!!
		//; here must be prefetch
		prefetcht0 _pi;
		// mov ecx, 16;
		lea ebx, [_pi];

		pextrb al, xmm0, 0; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 0; // store result in xmm0 vector
		pextrb al, xmm0, 1; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 1; // store result in xmm0 vector
		pextrb al, xmm0, 2; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 2; // store result in xmm0 vector
		pextrb al, xmm0, 3; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 3; // store result in xmm0 vector
		pextrb al, xmm0, 4; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 4; // store result in xmm0 vector
		pextrb al, xmm0, 5; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 5; // store result in xmm0 vector
		pextrb al, xmm0, 6; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 6; // store result in xmm0 vector
		pextrb al, xmm0, 7; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 7; // store result in xmm0 vector
		pextrb al, xmm0, 8; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 8; // store result in xmm0 vector
		pextrb al, xmm0, 9; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 9; // store result in xmm0 vector
		pextrb al, xmm0, 10; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 10; // store result in xmm0 vector
		pextrb al, xmm0, 11; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 11; // store result in xmm0 vector
		pextrb al, xmm0, 12; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 12; // store result in xmm0 vector
		pextrb al, xmm0, 13; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 13; // store result in xmm0 vector
		pextrb al, xmm0, 14; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 14; // store result in xmm0 vector
		pextrb al, xmm0, 15; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 15; // store result in xmm0 vector
	}
	L();
	_asm {
		mov edi, a;
		movdqu [edi], xmm0;
	}
	return;
}

void F(unsigned char* k, unsigned char* a1, unsigned char* a0) {
	LSX(a1, k); // in k is result of operation
	_asm {
		mov esi, k;
		mov edi, a0;
		movdqu xmm0, [esi];
		movdqu xmm1, [edi];
		pxor xmm0, xmm1;
		
		mov esi, a1;
		movdqu xmm1, [esi];
		movdqu [edi], xmm1; // copy a1 in a0
		movdqu [esi], xmm0;
	}
}

void L() {
	_asm {
		// mov edi, a;
		// movdqu xmm0, [edi];
		// pslldq xmm0, 3;
		//; here must be prefetch too
		prefetcht0 lookup_table;
		mov ecx, 16;
_L_func:
		lea ebx, [lookup_table];

		pextrb al, xmm0, 0; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 0; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 1; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 1; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 2; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 2; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 3; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 3; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 4; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 4; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 5; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 5; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 6; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 6; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 7; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 7; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 8; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 8; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 9; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 9; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 10; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 10; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 11; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 11; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 12; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 12; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 13; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 13; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 14; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 14; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 15; // load to al byte from xmm0 vector
		xlat;
// al is result of the last multiplication
		mov edx, ecx;
		mov ecx, 15;
_xor_l_lin_res_L:
		pextrb bl, xmm4, 0;
		xor al, bl;
		psrldq xmm4, 1;
		loop _xor_l_lin_res_L;
		mov ecx, edx;
		pslldq xmm0, 1; // shift vector to the left
		pinsrb xmm0, al, 0; // insert result of linear operation in front of the vector

		dec ecx;
		test ecx, ecx;
		jnz _L_func;
	}
}

void L_inv(/* argument is in xmm0 */) {

	_asm {
			mov ecx, 16;
			prefetcht0 lookup_table;
_L_func_inv:
		lea ebx, [lookup_table];
		

		pextrb al, xmm0, 0; 
		psrldq xmm0, 1;
		pinsrb xmm0, al, 15;

		pextrb al, xmm0, 0; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 0; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 1; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 1; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 2; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 2; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 3; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 3; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 4; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 4; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 5; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 5; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 6; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 6; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 7; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 7; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 8; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 8; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 9; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 9; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 10; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 10; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 11; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 11; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 12; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 12; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 13; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 13; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 14; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm4, al, 14; // store result in xmm4 vector
		add ebx, 256;

		pextrb al, xmm0, 15; // load to al byte from xmm0 vector
		xlat;
		// al is result of the last multiplication
		mov edx, ecx;
		mov ecx, 15;
_xor_l_lin_res_L_inv:
		pextrb bl, xmm4, 0;
		xor al, bl;
		psrldq xmm4, 1;
		loop _xor_l_lin_res_L_inv;
		mov ecx, edx;

		pinsrb xmm0, al, 15; // insert result of linear operation in front of the vector

		dec ecx;
		test ecx, ecx;
		jnz _L_func_inv;
	}
}

void S_inv_L_inv_X(unsigned char* k, unsigned char* a) {
	
	_asm {
		mov esi, k;
		mov edi, a;
		movdqu xmm2, [esi];
		movdqu xmm0, [edi];
		pxor xmm0, xmm2;
	}
	L_inv();
	_asm {
		// movdqu [edi], xmm1;  !!!
		prefetcht0 _pi_inv;
			// mov ecx, 16;
		lea ebx, [_pi_inv];
		

		pextrb al, xmm0, 0; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 0; // store result in xmm0 vector
		pextrb al, xmm0, 1; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 1; // store result in xmm0 vector
		pextrb al, xmm0, 2; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 2; // store result in xmm0 vector
		pextrb al, xmm0, 3; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 3; // store result in xmm0 vector
		pextrb al, xmm0, 4; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 4; // store result in xmm0 vector
		pextrb al, xmm0, 5; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 5; // store result in xmm0 vector
		pextrb al, xmm0, 6; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 6; // store result in xmm0 vector
		pextrb al, xmm0, 7; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 7; // store result in xmm0 vector
		pextrb al, xmm0, 8; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 8; // store result in xmm0 vector
		pextrb al, xmm0, 9; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 9; // store result in xmm0 vector
		pextrb al, xmm0, 10; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 10; // store result in xmm0 vector
		pextrb al, xmm0, 11; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 11; // store result in xmm0 vector
		pextrb al, xmm0, 12; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 12; // store result in xmm0 vector
		pextrb al, xmm0, 13; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 13; // store result in xmm0 vector
		pextrb al, xmm0, 14; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 14; // store result in xmm0 vector
		pextrb al, xmm0, 15; // load to al byte from xmm0 vector
		xlat;
		pinsrb xmm0, al, 15; // store result in xmm0 vector

		mov edi, a;
		movdqu [edi], xmm0;
	}
	return;
}