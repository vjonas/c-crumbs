/*
 * aes-gcm.h: Advanced Encryption Standard Galois/Counter Mode (AES-GCM)
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/aes-gcm.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Implements the AES-GCM authenticated encryption and decryption functions
 * for 128-bit keys.
 *
 * Uses the aes_encrypt function in aes.h, so you need to include that too:
 * #include "aes.h"
 * #include "aes-gcm.h"
 *
 * References:
 * [GCM] Recommendation for Block Cipher Modes of Operation:
 *       Galois/Counter Mode (GCM) and GMAC,
 *       NIST Special Publication 800-38D, November 2007
 *       http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
 */

/*
 * Computes the multiplication of blocks X and Y and stores the result in X.
 * x: pointer to 16 bytes (128 bits) of memory with X
 * y: pointer to 16 bytes (128 bits) of memory with Y
 *
 * [GCM] 6.3 Multiplication Operation on Blocks
 */
static void aes_gcm_mul(void *x, const void *y) {
  unsigned char z[16];
  unsigned char v[16];
  unsigned char lsb1;
  int i, j;

  /* Step 2. Z0 = 0^128 and V0 = Y */
  for (i = 0; i < 16; i++) {
    z[i] = 0;
    v[i] = ((unsigned char *)y)[i];
  }

  /*
   * Step 3. For (bit) i = 0 to 127, calculate blocks Zi+1 and Vi+1 as follows:
   * Zi+1 = Zi            if xi = 0
   * Zi+1 = Zi ^ Vi       if xi = 1
   * Vi+1 = Vi >> 1       if LSB1(Vi) = 0
   * Vi+1 = (Vi >> 1) ^ R if LSB1(Vi) = 1
   */
  for (i = 0; i < 128; i++) {
    if (((unsigned char *)x)[i >> 3] & (0x80 >> (i & 7))) {
      for (j = 0; j < 16; j++) {
        z[j] ^= v[j];
      }
    }
    lsb1 = v[15] & 1;
    for (j = 15; j > 0; j--) {
      v[j] = (v[j] >> 1) | (v[j-1] << 7);
    }
    v[0] >>= 1;
    if (lsb1) {
      v[0] ^= 0xe1; /* R = 11100001 || 0^128 */
    }
  }

  /* Step 4. Return Z_128 */
  for (i = 0; i < 16; i++) {
    ((unsigned char *)x)[i] = z[i];
  }
}

/*
 * Calculates an authentication tag.
 * tag: pointer to 16 bytes (128 bits) of memory to store the calculated tag
 * iv: pointer to the initialization vector (12 bytes (96 bits))
 * aad: pointer to the additional authenticated data
 * aad_length: number of bytes of the additional authenticated data
 * text: pointer to the text (plaintext or ciphertext)
 * text_length: number of bytes of the text
 * key: pointer to the encryption key (16 bytes (128 bits))
 *
 * Used internally by the aes_gcm_encrypt and aes_gcm_decrypt functions.
 * Can also be called externally to calculate just a GMAC:
 * aes_gcm_tag(gmac, iv, aad, aad_length, NULL, 0, key)
 *
 * [GCM] 6.4 GHASH Function
 * [GCM] 6.5 GCTR Function
 * [GCM] 7.1 Algorithm for the Authenticated Encryption Function
 */
static void aes_gcm_tag(void *tag, const void *iv, const void *aad, int aad_length, const void *text, int text_length, const void *key) {
  unsigned char h[16];  /* the hash subkey */
  unsigned char j0[16];  /* the pre-counter block */
  int i, j;

  /* [GCM] 7.1 Step 1. H = CIPH_K(0^128) */
  for (i = 0; i < 16; i++) {
    h[i] = 0;
  }
  aes_encrypt(h, h, key);

  /* [GCM] 7.1 Step 5. S = GHASH_H(A || 0^v || C || 0^u || len(A)64 || len(C)64) */
  for (i = 0; i < 16; i++) {
    ((unsigned char *)tag)[i] = 0;
  }
  for (i = 0; i < aad_length; i += 16) {
    for (j = 0; j < 16 && i + j < aad_length; j++) {
      ((unsigned char *)tag)[j] ^= ((unsigned char *)aad)[i + j];
    }
    aes_gcm_mul(tag, h);
  }
  for (i = 0; i < text_length; i += 16) {
    for (j = 0; j < 16 && i + j < text_length; j++) {
      ((unsigned char *)tag)[j] ^= ((unsigned char *)text)[i + j];
    }
    aes_gcm_mul(tag, h);
  }
  /*
  ((unsigned char *)tag)[0] ^= aad_length >> 53;
  ((unsigned char *)tag)[1] ^= aad_length >> 45;
  ((unsigned char *)tag)[2] ^= aad_length >> 37;
  */
  ((unsigned char *)tag)[3] ^= aad_length >> 29;
  ((unsigned char *)tag)[4] ^= aad_length >> 21;
  ((unsigned char *)tag)[5] ^= aad_length >> 13;
  ((unsigned char *)tag)[6] ^= aad_length >> 5;
  ((unsigned char *)tag)[7] ^= aad_length << 3;
  /*
  ((unsigned char *)tag)[8] ^= text_length >> 53;
  ((unsigned char *)tag)[9] ^= text_length >> 45;
  ((unsigned char *)tag)[10] ^= text_length >> 37;
  */
  ((unsigned char *)tag)[11] ^= text_length >> 29;
  ((unsigned char *)tag)[12] ^= text_length >> 21;
  ((unsigned char *)tag)[13] ^= text_length >> 13;
  ((unsigned char *)tag)[14] ^= text_length >> 5;
  ((unsigned char *)tag)[15] ^= text_length << 3;
  aes_gcm_mul(tag, h);

  /* [GCM] 7.1 Step 6. T = MSBt(GCTRk(J0,S)) */
  for (i = 0; i < 12; i++) {
    j0[i] = ((unsigned char *)iv)[i];
  }
  j0[12] = 0;
  j0[13] = 0;
  j0[14] = 0;
  j0[15] = 1;
  aes_encrypt(j0, j0, key);
  for (i = 0; i < 16; i++) {
    ((unsigned char *)tag)[i] ^= j0[i];
  }
}

/*
 * Implements the steps that are common to the encryption and decryption:
 * steps 2 and 3 of the authenticated encryption function and
 * steps 3 and 4 of the authenticated decryption function.
 * 
 * output: pointer to input_length bytes of memory to store the ciphertext/plaintext
 * iv: pointer to the 12-byte (96-bit) initialization vector
 * input: pointer to the plaintext/ciphertext
 * input_length: number of bytes of the input
 * aad: pointer to the additional authenticated data
 * aad_length: number of bytes of the additional authenticated data
 * key: pointer to the 16-byte (128-bit) key
 *
 * [GCM] 7.1 Algorithm for the Authenticated Encryption Function
 * [GCM] 7.2 Algorithm for the Authenticated Decryption Function
 */
static void aes_gcm_encrypt_or_decrypt(void *output, const void *iv, const void *input, int input_length, const void *key) {
  unsigned char cb[16];  /* the counter block CBi */
  unsigned counter;
  int i, m;

  /* J0 = IV || 0^31 || 1 */
  for (i = 0; i < 12; i++) {
    cb[i] = ((unsigned char *)iv)[i];
  }
  counter = 1;

  /* C = GCTR_K(inc32(J0), P) */
  for (m = 0; m < input_length - 16; m += 16) {
    /* [GCM] 6.5 GCTR Function, 5. For i = 2 to n, let CBi = inc32(CBi-1) */
    counter++;
    cb[12] = counter >> 24;
    cb[13] = counter >> 16;
    cb[14] = counter >> 8;
    cb[15] = counter;
    /* [GCM] 6.5 GCTR Function, 6. For i = 1 to n - 1, let Yi = Xi ^ CIPHk(CBi) */
    aes_encrypt((unsigned char *)output + m, cb, key);
    for (i = 0; i < 16; i++) {
      ((unsigned char *)output)[m + i] ^= ((unsigned char *)input)[m + i];
    }
  }
  /* [GCM] 6.5 GCTR Function, Step 7. Let Yn = Xn ^ MSBlen(Xn)(CIPHk(CBn)) */
  counter++;
  cb[12] = counter >> 24;
  cb[13] = counter >> 16;
  cb[14] = counter >> 8;
  cb[15] = counter;
  aes_encrypt(cb, cb, key);
  for (i = 0; i < input_length - m; i++) {
    ((unsigned char *)output)[m + i] = ((unsigned char *)input)[m + i] ^ cb[i];
  }
}

/*
 * Implements the AES-GCM authenticated encryption algorithm.
 *
 * Outputs:
 * ciphertext: pointer to plaintext_length bytes of memory to store the ciphertext
 * tag: pointer to 16 bytes (128 bits) of memory to store the authentication tag
 *
 * Inputs:
 * iv: pointer to the initialization vector (12 bytes (96 bits))
 * plaintext: pointer to the plaintext
 * plaintext_length: number of bytes of the plaintext
 * aad: pointer to the additional authenticated data
 * aad_length: number of bytes of the additional authenticated data
 * key: pointer to the 16-byte (128-bit) key
 *
 * [GCM] 7.1 Algorithm for the Authenticated Encryption Function
 */
static void aes_gcm_encrypt(void *ciphertext, void *tag, const void *iv, const void *plaintext, int plaintext_length, const void *aad, int aad_length, const void *key) {
  /* Encrypt the plaintext */
  aes_gcm_encrypt_or_decrypt(ciphertext, iv, plaintext, plaintext_length, key);
  /* Calculate the tag */
  aes_gcm_tag(tag, iv, aad, aad_length, ciphertext, plaintext_length, key);
}

/*
 * Implements the AES-GCM authenticated decryption algorithm.
 *
 * Outputs:
 * plaintext: pointer to ciphertext_length bytes of memory to store the plaintext
 *
 * Inputs:
 * iv: pointer to the initialization vector (12 bytes (96 bits))
 * ciphertext: pointer to the ciphertext
 * ciphertext_length: number of bytes of the ciphertext
 * aad: pointer to the additional authenticated data
 * aad_length: number of bytes of the additional authenticated data
 * tag: pointer to the authentication tag
 * tag_length: number of bytes of the authentication tag
 * key: pointer to the 16-byte (128-bit () key
 *
 * Returns 0 on success, or -1 if the verification of the tag fails.
 *
 * [GCM] 7.2 Algorithm for the Authenticated Decryption Function
 */
static int aes_gcm_decrypt(void *plaintext, const void *iv, const void *ciphertext, int ciphertext_length, const void *aad, int aad_length, const void *tag, int tag_length, const void *key) {
  unsigned char t[16];  /* the calculated tag */
  int i;

  /* Check the tag */
  aes_gcm_tag(t, iv, aad, aad_length, ciphertext, ciphertext_length, key);
  for (i = 0; i < tag_length; i++) {
    if (t[i] != ((unsigned char *)tag)[i]) {
      return -1;
    }
  }

  /* Decrypt the ciphertext */
  aes_gcm_encrypt_or_decrypt(plaintext, iv, ciphertext, ciphertext_length, key);

  return 0;
}
