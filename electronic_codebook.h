#ifndef ELECTRONIC_CODEBOOK
#define ELECTRONIC_CODEBOOK

void ecodebook_crypt(unsigned char* text, unsigned char master_key[32], unsigned long len);
void ecodebook_decrypt(unsigned char* ciphertext, unsigned char master_key[32], unsigned long len);

#endif