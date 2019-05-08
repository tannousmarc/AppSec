/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include "target.h"
// #include "unprotected.c"
#include "protected.c"

/** Read  an octet string (or sequence of bytes) from the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[out] r the destination octet string read
  * \return       the number of octets read
  */
 int hexToDec(char hex){
   return hex > '9' ? hex - 55 : hex - '0';
 }

 int _octetstr_rd( uint8_t* r, int n_r, char* x ) {
   int length = hexToDec(x[0]) * 16 + hexToDec(x[1]);

   int octetsRead = 0;
   // start past the colon character and read 2 by 2
   for(int i = 3; i < 3 + length * 2; i += 2){
     int parsed = hexToDec(x[i]) * 16 + hexToDec(x[i + 1]);
     r[octetsRead] = parsed;
     octetsRead++;
   }
   return octetsRead;
 }

int octetstr_rd(uint8_t* r, int n_r) {
  // 2-char length, 1-char colon, 2*n_r-char data, 1-char terminator
  char x[ 2 + 1 + 2 * ( n_r ) + 1 ];

  for( int i = 0; true; i++ ) {
   x[ i ] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );

   if( x[ i ] == '\x0D' ) {
     x[ i ] = '\x00'; break;
   }
  }

  return _octetstr_rd( r, n_r, x );
}

/** Write an octet string (or sequence of bytes) to   the UART, using a simple
  * length-prefixed, little-endian hexadecimal format.
  *
  * \param[in]  r the source      octet string written
  * \param[in]  n the number of octets written
  */
void decToHex(const uint8_t dec, char* result){
  int temp1 = dec & 0x0F;
  int temp0 = (dec >> 4) & 0x0F;

  result[1] = temp1 <= 9 ? '0' + temp1 : 'A' + (temp1 - 10);
  result[0] = temp0 <= 9 ? '0' + temp0 : 'A' + (temp0 - 10);
}

void octetstr_wr( const uint8_t* x, int n_x ) {
  char temp[2];
  decToHex(n_x, temp);
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, temp[0]);
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, temp[1]);
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, ':');

  for(int i = 0; i < n_x; i++){
    decToHex(x[i], temp);
    scale_uart_wr(SCALE_UART_MODE_BLOCKING, temp[0]);
    scale_uart_wr(SCALE_UART_MODE_BLOCKING, temp[1]);
  }
  scale_uart_wr(SCALE_UART_MODE_BLOCKING, '\x0D');
  return;
}

/** Initialise an AES-128 encryption, e.g., expand the cipher key k into round
  * keys, or perform randomised pre-computation in support of a countermeasure;
  * this can be left blank if no such initialisation is required, because the
  * same k and r will be passed as input to the encryption itself.
  *
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes_init(                               const uint8_t* k, const uint8_t* r ) {
  return;
}

/** Perform    an AES-128 encryption of a plaintext m under a cipher key k, to
  * yield the corresponding ciphertext c.
  *
  * \param[out] c   an   AES-128 ciphertext
  * \param[in]  m   an   AES-128 plaintext
  * \param[in]  k   an   AES-128 cipher key
  * \param[in]  r   some         randomness
  */

void aes     ( uint8_t* c, const uint8_t* m, const uint8_t* k, const uint8_t* r ) {
  aes_enc(c, m, k, r);
}

/** Initialise the SCALE development board, then loop indefinitely, reading a
  * command then processing it:
  *
  * 1. If command is inspect, then
  *
  *    - write the SIZEOF_BLK parameter,
  *      i.e., number of bytes in an  AES-128 plaintext  m, or ciphertext c,
  *      to the UART,
  *    - write the SIZEOF_KEY parameter,
  *      i.e., number of bytes in an  AES-128 cipher key k,
  *      to the UART,
  *    - write the SIZEOF_RND parameter,
  *      i.e., number of bytes in the         randomness r.
  *      to the UART.
  *
  * 2. If command is encrypt, then
  *
  *    - read  an   AES-128 plaintext  m from the UART,
  *    - read  some         randomness r from the UART,
  *    - initalise the encryption,
  *    - set the trigger signal to 1,
  *    - execute   the encryption, producing the ciphertext
  *
  *      c = AES-128.Enc( m, k )
  *
  *      using the hard-coded cipher key k plus randomness r if/when need be,
  *    - set the trigger signal to 0,
  *    - write an   AES-128 ciphertext c to   the UART.
  */

int main( int argc, char* argv[] ) {
  if( !scale_init( &SCALE_CONF ) ) {
    return -1;
  }

  // original key: { 0x06, 0x5C, 0x86, 0x80, 0xA0, 0xE9, 0x5F, 0x8C, 0xDC, 0xF2, 0xFB, 0xC5, 0xD8, 0xCE, 0xF2, 0xF6 }
  // PDF test key: { 0xCD, 0x97, 0x16, 0xE9, 0x5B, 0x42, 0xDD, 0x48, 0x69, 0x77, 0x2A, 0x34, 0x6A, 0x7F, 0x58, 0x13 }
  uint8_t cmd[ 1 ], c[ SIZEOF_BLK ], m[ SIZEOF_BLK ], k[ SIZEOF_KEY ] = { 0x06, 0x5C, 0x86, 0x80, 0xA0, 0xE9, 0x5F, 0x8C, 0xDC, 0xF2, 0xFB, 0xC5, 0xD8, 0xCE, 0xF2, 0xF6  }, r[ SIZEOF_RND ];
  while( true ) {
    if( 1 != octetstr_rd( cmd, 1 ) ) {
      break;
    }

    switch( cmd[ 0 ] ) {
      case COMMAND_INSPECT : {
        uint8_t t = SIZEOF_BLK;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_KEY;
                    octetstr_wr( &t, 1 );
                t = SIZEOF_RND;
                    octetstr_wr( &t, 1 );

        break;
      }
      case COMMAND_ENCRYPT : {
        if( SIZEOF_BLK != octetstr_rd( m, SIZEOF_BLK ) ) {
          break;
        }
        if( SIZEOF_RND != octetstr_rd( r, SIZEOF_RND ) ) {
          break;
        }

        aes_init(       k, r );

        scale_gpio_wr( SCALE_GPIO_PIN_TRG,  true );
        aes     ( c, m, k, r );
        scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );

                          octetstr_wr( c, SIZEOF_BLK );

        break;
      }
      default : {
        break;
      }
    }
  }

  return 0;
}
