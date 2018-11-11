/*
 * aes-kw.h: Advanced Encryption Standard (AES) Key Wrap algorithm
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/aes-kw.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Computes the AES Key Wrap algorithm.
 * ciphertext: pointer to ((n + 1) * 8) bytes to store the ciphertext
 * plaintext: pointer to (n * 8) bytes with the plaintext
 * n: number of 8-byte blocks of the plaintext (n = length(plaintext) / 8)
 * key: pointer to 16 bytes (128 bits) with the key encryption key
 *
 * Uses the aes_encrypt function in aes.h, so you need to include that too:
 * #include "aes.h"
 * #include "aes-kw.h"
 *
 * References:
 * [RFC3394] Advanced Encryption Standard (AES) Key Wrap Algorithm, 2002.
 */
static void aes_kw(void *ciphertext, const void *plaintext, int n, const void *key) {
  unsigned char x[16];
  unsigned char *r;
  unsigned char *c;
  int i, j, w;

  /* 1) Initialize variables. */
  for (w = 0; w < 8; w++) {  /* A0 = IV = 0xa6a6a6a6a6a6a6a6 */
    x[w] = 0xa6;
  }
  r = (unsigned char *)plaintext;  /* R[i] = P[i] */

  /* 2) Calculate intermediate values. */
  for (j = 0; j <= 5; j++) {
    c = (unsigned char *)ciphertext + 8;
    for (i = 1; i <= n; i++) {
      for (w = 8; w < 16; w++) {  /* A | R[i] */
        x[w] = *r++;
      }
      aes_encrypt(x, x, key);  /* B = AES(K, A | R[i]) */
      x[7] ^= n * j + i;  /* A = MSB(64, B) ^ t  (assume n < 43) */
      for (w = 8; w < 16; w++) {  /* R[i] = LSB(64, B) */
        *c++ = x[w];
      }
    }
    r = (unsigned char *)ciphertext + 8;
  }

  /* 3) Output the results. */
  for (w = 0; w < 8; w++) {
    ((unsigned char *)ciphertext)[w] = x[w];
  }
}
