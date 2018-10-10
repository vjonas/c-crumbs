/*
 * sha256.h: Secure Hash Algorithm 256 (SHA-256)
 *
 * https://github.com/andrebdo/c-crumbs/sha256.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Computes the SHA-256 message digest of a message.
 * digest: pointer to 32 bytes (256 bits) of memory to store the SHA-256 message digest
 * message: pointer to the input message
 * length: number of bytes of the input message
 *
 * References:
 * [SHS] Secure Hash Standard (FIPS PUB 180-4), Aug 2015
 *       http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 */
static void sha256(void *digest, const void *message, int length) {
  /* [SHS] 4.2.2 SHA-224 and SHA-256 Constants */
  const unsigned k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  };
  unsigned char pad[64];  /* padded block */
  unsigned w[16];  /* message schedule (ring buffer for a total of 64 elements) */
  unsigned h0, h1, h2, h3, h4, h5, h6, h7;  /* hash value words */
  unsigned a, b, c, d, e, f, g, h;  /* working variables */
  unsigned t1, t2, wt, wt2, wt7, wt15, ssig0wt15, ssig1wt2;
  const unsigned char *m;
  int i, j, t;

  /* [SHS] 5.3 Setting the Initial Hash Value H(0), 5.3.3 SHA-256 */
  h0 = 0x6a09e667;
  h1 = 0xbb67ae85;
  h2 = 0x3c6ef372;
  h3 = 0xa54ff53a;
  h4 = 0x510e527f;
  h5 = 0x9b05688c;
  h6 = 0x1f83d9ab;
  h7 = 0x5be0cd19;

  /* [SHS] 6.2.2 SHA-256 Hash Computation */
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

    /* 2. Initialize the eight working variables */
    a = h0;
    b = h1;
    c = h2;
    d = h3;
    e = h4;
    f = h5;
    g = h6;
    h = h7;

    /* 3. (transform the working variables) */
    for (t = 0; t < 64; t++) {
      /*
       * 1. Prepare the message schedule W (part 2):
       * For t = 16 to 63
       *    Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(t-15) + W(t-16)
       */
      wt2 = w[(t-2) & 15];
      ssig1wt2 = (wt2>>17)^(wt2<<15) ^ (wt2>>19)^(wt2<<13) ^ (wt2>>10);
      wt7 = w[(t-7) & 15];
      wt15 = w[(t-15) & 15];
      ssig0wt15 = (wt15>>7)^(wt15<<25) ^ (wt15>>18)^(wt15<<14) ^ (wt15>>3);
      wt = w[t & 15];
      w[t & 15] = ssig1wt2 + wt7 + ssig0wt15 + wt;

      /* T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt */
      t1 = h + ((e>>6)^(e<<26)^(e>>11)^(e<<21)^(e>>25)^(e<<7)) + ((e&f)^(~e&g)) + k[t] + wt;
      /* T2 = BSIG0(a) + MAJ(a,b,c) */
      t2 = ((a>>2)^(a<<30)^(a>>13)^(a<<19)^(a>>22)^(a<<10)) + ((a&b)^(a&c)^(b&c));
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    /* 4. Compute the ith intermediate hash value H(i) */
    h0 += a;
    h1 += b;
    h2 += c;
    h3 += d;
    h4 += e;
    h5 += f;
    h6 += g;
    h7 += h;
  }

  /* Store the resulting 256-bit message digest */
  ((unsigned char *)digest)[0] = h0 >> 24;
  ((unsigned char *)digest)[1] = h0 >> 16;
  ((unsigned char *)digest)[2] = h0 >> 8;
  ((unsigned char *)digest)[3] = h0;
  ((unsigned char *)digest)[4] = h1 >> 24;
  ((unsigned char *)digest)[5] = h1 >> 16;
  ((unsigned char *)digest)[6] = h1 >> 8;
  ((unsigned char *)digest)[7] = h1;
  ((unsigned char *)digest)[8] = h2 >> 24;
  ((unsigned char *)digest)[9] = h2 >> 16;
  ((unsigned char *)digest)[10] = h2 >> 8;
  ((unsigned char *)digest)[11] = h2;
  ((unsigned char *)digest)[12] = h3 >> 24;
  ((unsigned char *)digest)[13] = h3 >> 16;
  ((unsigned char *)digest)[14] = h3 >> 8;
  ((unsigned char *)digest)[15] = h3;
  ((unsigned char *)digest)[16] = h4 >> 24;
  ((unsigned char *)digest)[17] = h4 >> 16;
  ((unsigned char *)digest)[18] = h4 >> 8;
  ((unsigned char *)digest)[19] = h4;
  ((unsigned char *)digest)[20] = h5 >> 24;
  ((unsigned char *)digest)[21] = h5 >> 16;
  ((unsigned char *)digest)[22] = h5 >> 8;
  ((unsigned char *)digest)[23] = h5;
  ((unsigned char *)digest)[24] = h6 >> 24;
  ((unsigned char *)digest)[25] = h6 >> 16;
  ((unsigned char *)digest)[26] = h6 >> 8;
  ((unsigned char *)digest)[27] = h6;
  ((unsigned char *)digest)[28] = h7 >> 24;
  ((unsigned char *)digest)[29] = h7 >> 16;
  ((unsigned char *)digest)[30] = h7 >> 8;
  ((unsigned char *)digest)[31] = h7;
}
