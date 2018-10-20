/*
 * aes-mmo.h: AES Matyas-Meyer-Oseas (AES-MMO) hash function
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/aes-mmo.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Computes the Matyas-Meyer-Oseas hash function based on the AES-128 block cipher.
 *
 * Uses the aes_encrypt function in aes.h, so you need to include that too:
 * #include "aes.h"
 * #include "aes-mmo.h"
 *
 * digest: pointer to 16 bytes (128 bits) of memory to store the message digest output
 * message: input message
 * length: number of bytes of the input message
 *
 * Reference:
 * ZigBee specification, document 05-3474-21, Aug 2015,
 * section B.6 Block-Cipher-Based Cryptographic Hash Function.
 */
static void aes_mmo(void *digest, const void *message, int length) {
  int i, r;
  unsigned char p[16];

  /* Hash0 = 0^(8n)  n-octet all-zero bit string */
  for (i = 0; i < 16; i++) {
    ((char *)digest)[i] = 0;
  }

  /* Hashj = E(Hashj-1,Mj) xor Mj */
  for (r = 0; r <= length - 16; r += 16) {
    aes_encrypt(digest, (char *)message + r, digest);
    for (i = 0; i < 16; i++) {
      ((char *)digest)[i] ^= ((char *)message)[r + i];
    }
  }

  /* Build and process the final padded block(s) */
  r = length & 15;
  for (i = 0; i < r; i++) {
    p[i] = ((char *)message)[(length & ~15) + i];
  }
  p[r++] = 0x80;
  if ((length < 8192 && r > 14) || (length >= 8192 && r > 10)) {
    /* The first of 2 padded blocks */
    for (i = r; i < 16; i++) {
      p[i] = 0;
    }
    aes_encrypt(digest, p, digest);
    for (i = 0; i < 16; i++) {
      ((char *)digest)[i] ^= p[i];
    }
    r = 0;
  }
  /* The final padded block with the length in bits */
  if (length < 8192) {
    for (i = r; i < 14; i++) {
      p[i] = 0;
    }
    p[14] = length >> 5;
    p[15] = length << 3;
  } else {
    for (i = r; i < 10; i++) {
      p[i] = 0;
    }
    p[10] = length >> 21;
    p[11] = length >> 13;
    p[12] = length >> 5;
    p[13] = length << 3;
    p[14] = 0;
    p[15] = 0;
  }
  aes_encrypt(digest, p, digest);
  for (i = 0; i < 16; i++) {
    ((char *)digest)[i] ^= p[i];
  }
}
