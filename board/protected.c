/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "encrypt.h"

aes_gf28_t xtime( aes_gf28_t a ){
  if((a & 0x80) == 0x80){
    return 0x1B ^ (a << 1);
  }
  else{
    return (a << 1);
  }
}

aes_gf28_t mul(aes_gf28_t a, aes_gf28_t b){
  aes_gf28_t intermediate = 0;
  for(int i = 7; i >= 0; i--){
    intermediate = xtime(intermediate);
    if((b >> i) & 1){
      intermediate ^= a;
    }
  }
  return intermediate;
}

aes_gf28_t inv(aes_gf28_t a){
  aes_gf28_t t_0;
  aes_gf28_t t_1;
  // a ^ 2
  t_0 = mul(a, a);
  // a ^ 3
  t_1 = mul(t_0, a);
  // a ^ 4
  t_0 = mul(t_0, t_0);
  // a ^ 7
  t_1 = mul(t_0, t_1);
  // a ^ 8
  t_0 = mul(t_0, t_0);
  // a ^ 15
  t_0 = mul(t_0, t_1);
  // a ^ 30
  t_0 = mul(t_0, t_0);
  // a ^ 60
  t_0 = mul(t_0, t_0);
  // a ^ 67
  t_1 = mul(t_0, t_1);
  // a ^ 127
  t_0 = mul(t_0, t_1);
  // a ^ 254
  t_0 = mul(t_0, t_0);

  return t_0;
}

unsigned char sbox_mascat[256];
unsigned char rijndael_sbox[256] = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                          0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                          0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                          0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                          0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                          0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                          0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                          0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                          0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                          0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                          0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                          0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                          0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                          0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                          0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                          0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};
aes_gf28_t sbox(aes_gf28_t a){
  return rijndael_sbox[a];
}

void aes_enc_exp_step(aes_gf28_t* r, const aes_gf28_t* rk, aes_gf28_t rc){
  r[0] = rc ^ sbox(rk[13]) ^ rk[0];
  r[1] =      sbox(rk[14]) ^ rk[1];
  r[2] =      sbox(rk[15]) ^ rk[2];
  r[3] =      sbox(rk[12]) ^ rk[3];

  r[4] =             r[0] ^ rk[4];
  r[5] =             r[1] ^ rk[5];
  r[6] =             r[2] ^ rk[6];
  r[7] =             r[3] ^ rk[7];

  r[8] =             r[4] ^ rk[8];
  r[9] =             r[5] ^ rk[9];
  r[10] =           r[6] ^ rk[10];
  r[11] =           r[7] ^ rk[11];

  r[12] =           r[8] ^ rk[12];
  r[13] =           r[9] ^ rk[13];
  r[14] =          r[10] ^ rk[14];
  r[15] =          r[11] ^ rk[15];
}

void aes_enc_rnd_key(aes_gf28_t* s, const aes_gf28_t* rk, const aes_gf28_t masca, const aes_gf28_t* mascaColoane){
  for(int i = 0; i < 16; i++){
    s[i] = s[i] ^ rk[i] ^ mascaColoane[i] ^ masca;
  }
}

void aes_enc_rnd_sub(aes_gf28_t* s){
  for(int i = 0; i < 16; i++){
    s[i] = sbox_mascat[s[i]];
  }
}

#define AES_ENC_RND_ROW_STEP(a,b,c,d,e,f,g,h){ \
  aes_gf28_t __a1 = s[a];                      \
  aes_gf28_t __b1 = s[b];                      \
  aes_gf28_t __c1 = s[c];                      \
  aes_gf28_t __d1 = s[d];                      \
  s[e] = __a1;                                 \
  s[f] = __b1;                                 \
  s[g] = __c1;                                 \
  s[h] = __d1;                                 \
}

void aes_enc_rnd_row(aes_gf28_t* s){
  AES_ENC_RND_ROW_STEP(1,5,9,13,13,1,5,9);
  AES_ENC_RND_ROW_STEP(2,6,10,14,10,14,2,6);
  AES_ENC_RND_ROW_STEP(3,7,11,15,7,11,15,3);
}

#define AES_ENC_RND_MIX_STEP(a,b,c,d) {      \
  aes_gf28_t __a1 = s[ a ];                  \
  aes_gf28_t __b1 = s[ b ];                  \
  aes_gf28_t __c1 = s[ c ];                  \
  aes_gf28_t __d1 = s[ d ];                  \
  aes_gf28_t __a2 = xtime( __a1 );           \
  aes_gf28_t __b2 = xtime( __b1 );           \
  aes_gf28_t __c2 = xtime( __c1 );           \
  aes_gf28_t __d2 = xtime( __d1 );           \
  aes_gf28_t __a3 = __a1 ^ __a2;             \
  aes_gf28_t __b3 = __b1 ^ __b2;             \
  aes_gf28_t __c3 = __c1 ^ __c2;             \
  aes_gf28_t __d3 = __d1 ^ __d2;             \
  s[ a ] = __a2 ^ __b3 ^ __c1 ^ __d1;        \
  s[ b ] = __a1 ^ __b2 ^ __c3 ^ __d1;        \
  s[ c ] = __a1 ^ __b1 ^ __c2 ^ __d3;        \
  s[ d ] = __a3 ^ __b1 ^ __c1 ^ __d2;        \
}

void aes_enc_rnd_mix(aes_gf28_t* s){
  for(int i = 0; i < 4; i++, s += 4){
    AES_ENC_RND_MIX_STEP(0, 1, 2, 3);
  }
}

void xorArrays(aes_gf28_t* a, aes_gf28_t* b){
  for (int i = 0; i < 16; i++) {
    a[i] = a[i] ^ b[i];
  }
}

void xorArrayByte(aes_gf28_t* a, aes_gf28_t b){
  for (int i = 0; i < 16; i++) {
    a[i] = a[i] ^ b;
  }
}

void aes_enc(uint8_t* r, const uint8_t* m, const uint8_t* k, const uint8_t* randomness) {
  aes_gf28_t masca = randomness[8];
  aes_gf28_t mascaMica1 = randomness[1];
  aes_gf28_t mascaMica2 = randomness[5];
  aes_gf28_t mascaMica3 = randomness[9];
  aes_gf28_t mascaMica4 = randomness[12];
  aes_gf28_t rk[ 4 * 4 ], s[ 4 * 4 ];
  aes_gf28_t rcp[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20 , 0x40, 0x80, 0x1B, 0x36};
  aes_gf28_t* rkp = rk;
  memcpy(s, m, 16 * sizeof(aes_gf28_t));
  memcpy(rkp, k, 16 * sizeof(aes_gf28_t));


  aes_gf28_t sMascat[16] = {mascaMica1, mascaMica2, mascaMica3, mascaMica4, mascaMica1, mascaMica2, mascaMica3, mascaMica4, mascaMica1, mascaMica2, mascaMica3, mascaMica4, mascaMica1, mascaMica2, mascaMica3, mascaMica4};


  aes_gf28_t coloaneMascate[16];
  memcpy(coloaneMascate, sMascat, 16 * sizeof(aes_gf28_t));
  aes_enc_rnd_mix(coloaneMascate);


  for(int i = 0; i < 256; i++){
    sbox_mascat[i ^ masca] = sbox(i) ^ masca;
  }

  int numberOfNops = randomness[3] % 10;

  for(int i = 0; i < numberOfNops; i++)
    asm volatile("nop");

  xorArrays(s, coloaneMascate);

  aes_enc_rnd_key( s, rkp, masca, coloaneMascate );

  for (int i = 1; i < 10; i++ ){
      aes_enc_rnd_sub( s       );
      aes_enc_rnd_row( s       );
      xorArrayByte(s, masca);
      xorArrays(s, sMascat);
      aes_enc_rnd_mix( s       );
      aes_enc_exp_step( rkp, rkp, rcp[i - 1]);
      aes_enc_rnd_key( s, rkp, masca, coloaneMascate);
    }

    aes_enc_rnd_sub( s       );
    aes_enc_rnd_row( s       );
    aes_enc_exp_step( rkp, rkp, rcp[9] );
    aes_enc_rnd_key( s, rkp, masca, coloaneMascate );
    xorArrays(s, coloaneMascate);
    memcpy(r, s, 16 * sizeof(aes_gf28_t));
}

// int main( int argc, char* argv[] ) {
//   uint8_t k[ 16 ] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
//                       0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
//   uint8_t m[ 16 ] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D,
//                       0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
//   uint8_t c[ 16 ] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB,
//                       0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
//   uint8_t t[ 16 ];
//   uint8_t result[ 16 ];
//
//   aes_enc(result, m, k);
//
//   AES_KEY rk;
//   AES_set_encrypt_key( k, 128, &rk );
//   AES_encrypt( m, t, &rk );
//
//   for(int i = 0; i < 16; i++){
//     printf("Expected: %3d Received: %3d \n", c[i],result[i]);
//   }
//
//   if( !memcmp( result, c, 16 * sizeof( uint8_t ) ) ) {
//     printf( "Encryption result is equal to c.\n" );
//   }
//   else {
//     printf( "Encryption result is not equal to c.\n" );
//   }
// }
