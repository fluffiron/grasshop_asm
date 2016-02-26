#include"kuznechik.h"
#include"electronic_codebook.h"
#include<Windows.h>

void ecodebook_crypt(unsigned char* text, unsigned char master_key[32], unsigned long len) {
	unsigned char keys[10][16] = {0};
	long long i = 0;
	// int time_ = 0;

#ifdef CHECK_TIME_RDTSC
	int time[2] = {0};
	unsigned long long res_time = 0;
#endif

	generate_keys(keys, master_key);

	// time_ = GetTickCount();

#ifdef CHECK_TIME_RDTSC
	_asm {
		// LFENCE;
		RDTSC;
		lea esi, [time];
		mov [esi], eax;
		mov [esi + 4], edx;
	}
#endif
	_asm{
		prefetcht1 text;
	}
	for( i = 0; i < len / 16; ++i) {
		kuz_encrypt(text + 16 * i, keys);
	}

	// time_ = GetTickCount() - time_;

	// return time_;

#ifdef CHECK_TIME_RDTSC
	_asm {
		// LFENCE;
		RDTSC;
		lea esi, [time];
		sub eax, [esi];
		sbb edx, [esi+4];
		mov [esi], eax;
		mov [esi + 4], edx;
	}
	res_time = time[1];
	res_time = (res_time << 32) + time[0];
	return res_time;
#endif
}

void ecodebook_decrypt(unsigned char* ciphertext, unsigned char master_key[32],  unsigned long len) {
	unsigned char keys[10][16] = {0};
	long long i = 0;

	// int time_ = 0;
#ifdef CHECK_TIME_RDTSC
	int time[2] = {0};
	unsigned long long res_time = 0;
#endif
	generate_keys(keys, master_key);
#ifdef CHECK_TIME_RDTSC
	_asm {
		LFENCE;
		RDTSC;
		lea esi, [time];
		mov [esi], eax;
		mov [esi + 4], edx;
	}
#endif
	//time_ = GetTickCount();

	_asm{
		prefetcht1 ciphertext;
	}

	for( i = 0; i < len / 16; ++i) {
		kuz_decrypt(ciphertext + 16 * i, keys);
	}
	//time_ = GetTickCount() - time_;
#ifdef CHECK_TIME_RDTSC
	_asm {
		LFENCE;
		RDTSC;
		lea esi, [time];
		sub eax, [esi];
		sbb edx, [esi+4];
		mov [esi], eax;
		mov [esi + 4], edx;
	}
	res_time = time[1];
	res_time = (res_time << 32) + time[0];
	return res_time;
#endif
	//return time_;
}