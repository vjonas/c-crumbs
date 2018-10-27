/*
 * aes-ccm.h: Advanced Encryption Standard Counter CBC MAC (AES-CCM)
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/aes-ccm.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Implements the AES-CCM encryption and decryption for 128-bit keys.
 *
 * Uses the aes_encrypt function in aes.h, so you need to include that too:
 * #include "aes.h"
 * #include "aes-ccm.h"
 *
 * References:
 * [CCM] Recommendation for Block Cipher Modes of Operation:
 *       The CCM Mode for Authentication and Confidentiality
 *       NIST Special Publication 800-38C, May 2004, errata update Jul 2007
 *       http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38c.pdf
 */

/*
 * Internal function that performs the Counter (CTR) mode
 * which is used for both encrypting a payload and decrypting
 * a ciphertext (the payload part only, excluding the MAC).
 *
 * output: pointer to input_length bytes to store the ciphertext/payload
 * nonce: pointer to the nonce
 * nonce_length: number of bytes of the nonce
 * input: pointer to the payload/ciphertext to encrypt/decrypt
 * input_length: number of bytes of the input payload/ciphertext
 * key: pointer to the 16-byte (128-bit) block cipher key
 *
 * References:
 * [CCM] 6.1 Generation-Encryption Process
 * [CCM] A.3 Formatting of the Counter Blocks
 */
static void aes_ccm_ctr(void *output, const void *nonce, int nonce_length, const void *input, int input_length, const void *key) {
  char x[16];
  int counter;
  int i, n;

  counter = 0;
  for (n = 0; n < input_length; n += 16) {
    /* Generate the counter block CTRj */
    x[0] = 14 - nonce_length;
    for (i = 0; i < nonce_length; i++) {
      x[i + 1] = ((char *)nonce)[i];
    }
    counter++;
    for (i = 0; i < 15 - nonce_length; i++) {
      if (i < (int)sizeof(counter)) {
        x[15 - i] = counter >> (i * 8);
      } else {
        x[15 - i] = 0;
      }
    }
    /* Sj = CIPHk(CTRj) */
    aes_encrypt(x, x, key);
    /* C = P xor MSBplen(S) */
    for (i = 0; i < 16 && n + i < input_length; i++) {
      ((char *)output)[n + i] = ((char *)input)[n + i] ^ x[i];
    }
  }
}

/*
 * Internal function that generates and encrypts a MAC.
 *
 * mac: pointer to mac_length bytes to store the encrypted MAC
 * mac_length: number of bytes of the MAC
 * nonce: pointer to the nonce
 * nonce_length: number of bytes of the nonce
 * ad: pointer to the associated data
 * ad_length: number of bytes of the associated data
 * payload: pointer to the payload
 * payload_length: number of bytes of the payload
 * key: pointer to the 16-byte (128-bit) block cipher key
 *
 * References:
 * [CCM] 6.1 Generation-Encryption Process
 * [CCM] A.2 Formatting of the Input Data
 */
static void aes_ccm_mac(void *mac, int mac_length, const void *nonce, int nonce_length, const void *ad, int ad_length, const void *payload, int payload_length, const void *key) {
  char x[16];
  int i, n;

  /* [CCM] A.2.1 Formatting of the Control Information and the Nonce */
  x[0] = (ad_length > 0) << 6 | ((mac_length - 2) / 2) << 3 | (14 - nonce_length);
  for (i = 0; i < nonce_length; i++) {
    x[i + 1] = ((char *)nonce)[i];
  }
  for (i = 0; i < 15 - nonce_length; i++) {
    if (i < (int)sizeof(payload_length)) {
      x[15 - i] = payload_length >> (i * 8);
    } else {
      x[15 - i] = 0;
    }
  }
  /* Y0 = CIPHk(B0) */
  aes_encrypt(x, x, key);

  /* [CCM] A.2.2 Formatting of the Associated Data */
  if (ad_length > 0) {
    if (ad_length >= 0xff00) {
      x[0] ^= 0xff;
      x[1] ^= 0xfe;
      x[2] ^= ad_length >> 24;
      x[3] ^= ad_length >> 16;
      x[4] ^= ad_length >> 8;
      x[5] ^= ad_length;
      i = 6;
    } else {
      x[0] ^= ad_length >> 8;
      x[1] ^= ad_length;
      i = 2;
    }
    for (n = 0; n < ad_length; n++) {
      /* Yi = CIPHk(Bi xor Yi-1) */
      x[i++] ^= ((char *)ad)[n];
      if (i == 16) {
        i = 0;
        aes_encrypt(x, x, key);
      }
    }
    if (i) {
      aes_encrypt(x, x, key);
    }
  }

  /* [CCM] A.2.3 Formatting of the Payload */
  for (i = 0, n = 0; n < payload_length; n++) {
    /* Yi = CIPHk(Bi xor Yi-1) */
    x[i++] ^= ((char *)payload)[n];
    if (i == 16) {
      i = 0;
      aes_encrypt(x, x, key);
    }
  }
  if (i) {
    aes_encrypt(x, x, key);
  }

  /* Get the MAC: T = MSBtlen(Yr) */
  for (i = 0; i < mac_length; i++) {
    ((char *)mac)[i] = x[i];
  }

  /* Encrypt the MAC: U = T xor MSBlen(S0) */
  x[0] = 14 - nonce_length;
  for (i = 0; i < nonce_length; i++) {
    x[i + 1] = ((char *)nonce)[i];
  }
  for (i = 0; i < 15 - nonce_length; i++) {
    x[15 - i] = 0;
  }
  aes_encrypt(x, x, key);
  for (i = 0; i < mac_length; i++) {
    ((char *)mac)[i] ^= x[i];
  }
}

/*
 * Performs the AES-CCM generation-encryption process
 * (encrypts the payload and the appended MAC).
 *
 * ciphertext: pointer to (payload_length + mac_length) bytes to store the ciphertext
 * mac_length: number of bytes of the MAC
 * nonce: pointer to the nonce
 * nonce_length: number of bytes of the nonce
 * ad: pointer to the associated data
 * ad_length: number of bytes of the associated data
 * payload: pointer to the payload
 * payload_length: number of bytes of the payload
 * key: pointer to the 16-byte (128-bit) block cipher key
 *
 * Reference:
 * [CCM] 6.1 Generation-Encryption Process
 */
static void aes_ccm_encrypt(void *ciphertext, int mac_length, const void *nonce, int nonce_length, const void *ad, int ad_length, const void *payload, int payload_length, const void *key) {
  /* Encrypt the payload */
  aes_ccm_ctr(ciphertext, nonce, nonce_length, payload, payload_length, key);
  /* Encrypt and append the MAC */
  aes_ccm_mac((char *)ciphertext + payload_length, mac_length, nonce, nonce_length, ad, ad_length, payload, payload_length, key);
}

/*
 * Performs the AES-CCM decryption-validation process
 * (decrypts the ciphertext and checks and removes the MAC).
 * Returns 0 if the MAC verification succeeds, or -1 if it fails.
 *
 * payload: pointer to (ciphertext_length - mac_length) bytes to store the decrypted payload
 * mac_length: number of bytes of the MAC
 * nonce: pointer to the nonce
 * nonce_length: number of bytes of the nonce
 * ad: pointer to the associated data
 * ad_length: number of bytes of the associated data
 * ciphertext: pointer to the ciphertext
 * ciphertext_length: number of bytes of the ciphertext (including the encrypted MAC)
 * key: pointer to the 16-byte (128-bit) block cipher key
 *
 * Reference:
 * [CCM] 6.2 Decryption-Validation Process
 */
static int aes_ccm_decrypt(void *payload, int mac_length, const void *nonce, int nonce_length, const void *ad, int ad_length, const void *ciphertext, int ciphertext_length, const void *key) {
  char mac[16];
  int payload_length;
  int i;

  payload_length = ciphertext_length - mac_length;

  /* Decrypt the payload part of the ciphertext */
  aes_ccm_ctr(payload, nonce, nonce_length, ciphertext, payload_length, key);

  /* Calculate the encrypted MAC */
  aes_ccm_mac(mac, mac_length, nonce, nonce_length, ad, ad_length, payload, payload_length, key);

  /* Check the received and calculated MACs */
  for (i = 0; i < mac_length; i++) {
    if (mac[i] != ((char *)ciphertext)[payload_length + i]) {
      return -1;
    }
  }

  return 0;
}
