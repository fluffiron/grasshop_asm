#ifndef KUZNECHIK_H
#define KUZNECHIK_H

void generate_lookup_table(unsigned char lookup_table[][256]); //
void generate_keys(unsigned char keys[][16], unsigned char* master_key);    // the 1st ind the 2nd keys must be filled as a part of a masterkey
unsigned char polynoms_mult(unsigned char a, unsigned char b);
void LSX(unsigned char k[16], unsigned char a[16]); // result is in *a
void L(); // result is in xmm0
void F(unsigned char* k, unsigned char* a1, unsigned char* a0);
void kuz_encrypt(unsigned char text[16], unsigned char keys[10][16]); // result is in text;
void L_inv(); // result is in xmm0
void S_inv_L_inv_X(unsigned char k[16], unsigned char a[16]); // result is in *a
void kuz_decrypt(unsigned char text[16], unsigned char keys[10][16]);
void create_lookup_h();

#endif