/*
 * tests/sha256.c: tests for ../sha256.h
 *
 * https://github.com/andrebdo/c-crumbs/tests/sha256.c
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

#include "../sha256.h"
#include <stdio.h>
#include <string.h>

/*
 * Tests the sha256 function with the SHA-256 values in
 * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
 */
int main(int argc, char **argv) {
  const struct {
    const char *message;
    unsigned char digest[32];
  } vectors[] = {
    { /* One block message sample */
      "abc",
      {0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
       0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad}
    },{ /* Two block message sample */
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      {0x24,0x8d,0x6a,0x61,0xd2,0x06,0x38,0xb8,0xe5,0xc0,0x26,0x93,0x0c,0x3e,0x60,0x39,
       0xa3,0x3c,0xe4,0x59,0x64,0xff,0x21,0x67,0xf6,0xec,0xed,0xd4,0x19,0xdb,0x06,0xc1}
    }
  };
  unsigned char x[32];
  unsigned i;

  for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    sha256(x, vectors[i].message, strlen(vectors[i].message));
    if (memcmp(x, vectors[i].digest, 32)) {
      fprintf(stderr, "sha256() failed for test vector %u\n", i);
      return 1;
    }
  }

  return 0;
}
