/*
 * sha1.h: Secure Hash Algorithm 1 (SHA-1)
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/sha1.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Computes the SHA-1 message digest of a message.
 * digest: pointer to 20 bytes (160 bits) to store the SHA-1 message digest
 * message: pointer to the input message
 * length: number of bytes of the input message
 *
 * References:
 * [SHS] Secure Hash Standard (FIPS PUB 180-4), Aug 2015
 *       http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */
static void sha1(void *digest, const void *message, int length) {
  unsigned char pad[64];  /* padded block */
  unsigned w[16];  /* message schedule (ring buffer for a total of 80 elements) */
  unsigned h[5];  /* hash value words */
  unsigned a, b, c, d, e;  /* working variables */
  unsigned tmp, ft, kt, wt, wtr;
  unsigned char *m;
  int i, j, t;

  /* [SHS] 5.3 Setting the Initial Hash Value H(0), 5.3.1 SHA-1 */
  h[0] = 0x67452301;
  h[1] = 0xefcdab89;
  h[2] = 0x98badcfe;
  h[3] = 0x10325476;
  h[4] = 0xc3d2e1f0;

  /* [SHS] 6.1.2 SHA-1 Hash Computation */
  for (i = 0; i - 9 < length; i += 64) {  /* min pad = 9 bytes (0x80 + 64-bit length) */
    m = (unsigned char *)message + i;
    if (i > length - 64) {
      /* [SHS] 5.1 Padding the Message, 5.1.1 SHA-1, SHA-224 and SHA-256 */
      for (j = 0; j < length - i; j++) {
        pad[j] = m[j];
      }
      if (i + j == length) {
        pad[j++] = 0x80;
      }
      if (j > 56) {  /* penultimate block */
        while (j < 64) {
          pad[j++] = 0;
        }
      } else {  /* last block */
        while (j < 56) {
          pad[j++] = 0;
        }
        pad[56] = 0;  /* length >> 53; */
        pad[57] = 0;  /* length >> 45; */
        pad[58] = 0;  /* length >> 37; */
        pad[59] = length >> 29;
        pad[60] = length >> 21;
        pad[61] = length >> 13;
        pad[62] = length >> 5;
        pad[63] = length << 3;
      }
      m = pad;
    }

    /*
     * 1. Prepare the message schedule W (part 1):
     * For t = 0 to 15
     *    Wt = M(i)t
     */
    for (t = 0; t < 16; t++) {
      w[t] = m[t*4] << 24 | m[t*4+1] << 16 | m[t*4+2] << 8 | m[t*4+3];
    }

    /* 2. Initialize the five working variables */
    a = h[0];
    b = h[1];
    c = h[2];
    d = h[3];
    e = h[4];

    /* 3. (transform the working variables) */
    for (t = 0; t < 80; t++) {
      /*
       * 1. Prepare the message schedule W (part 2):
       * For t = 16 to 79
       *    Wt = ROTL1(W(t-3) ^ W(t-8) ^ W(t-14) ^ W(t-16)
       */
      wt = w[t & 15];
      wtr = w[(t-3) & 15] ^ w[(t-8) & 15] ^ w[(t-14) & 15] ^ wt;
      w[t & 15] = wtr << 1 | wtr >> 31;

      /*
       * T = ROTL5(a) + ft(b,c,d) + e + Kt + Wt
       * [SHS] 4.1.1 SHA-1 Functions, [SHS] 4.2.1 SHA-1 Constants
       */
      if (t < 20) {
        ft = (b & c) ^ (~b & d);
        kt = 0x5a827999;
      } else if (t < 40) {
        ft = b ^ c ^ d;
        kt = 0x6ed9eba1;
      } else if (t < 60) {
        ft = (b & c) ^ (b & d) ^ (c & d);
        kt = 0x8f1bbcdc;
      } else { /* if (t < 80) */
        ft = b ^ c ^ d;
        kt = 0xca62c1d6;
      }
      tmp = (a << 5 | a >> 27) + ft + e + kt + wt;

      e = d;
      d = c;
      c = b << 30 | b >> 2;
      b = a;
      a = tmp;
    }

    /* 4. Compute the ith intermediate hash value H(i) */
    h[0] += a;
    h[1] += b;
    h[2] += c;
    h[3] += d;
    h[4] += e;
  }

  /* Store the resulting 160-bit message digest */
  for (i = 0; i < 5; i++) {
    ((unsigned char *)digest)[i * 4 + 0] = h[i] >> 24;
    ((unsigned char *)digest)[i * 4 + 1] = h[i] >> 16;
    ((unsigned char *)digest)[i * 4 + 2] = h[i] >> 8;
    ((unsigned char *)digest)[i * 4 + 3] = h[i];
  }
}
