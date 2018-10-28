/*
 * tests/sha1.c: tests for ../sha1.h
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/tests/sha1.c
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

#include "../sha1.h"
#include <stdio.h>
#include <string.h>

/*
 * Tests the sha1 function with the SHA-1 values in
 * http://csrc.nist.gov/groups/ST/toolkit/documents/Examples/SHA_All.pdf
 */
int main(int argc, char **argv) {
  const struct {
    const char *message;
    unsigned char digest[20];
  } vectors[] = {
    { /* One block message sample */
      "abc",
      {0xa9,0x99,0x3e,0x36, 0x47,0x06,0x81,0x6a, 0xba,0x3e,0x25,0x71,
       0x78,0x50,0xc2,0x6c, 0x9c,0xd0,0xd8,0x9d}
    },{ /* Two block message sample */
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
      {0x84,0x98,0x3e,0x44, 0x1c,0x3b,0xd2,0x6e, 0xba,0xae,0x4a,0xa1,
       0xf9,0x51,0x29,0xe5, 0xe5,0x46,0x70,0xf1}
    }
  };
  unsigned char x[sizeof(vectors[0].digest)];
  unsigned i;

  for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    sha1(x, vectors[i].message, strlen(vectors[i].message));
    if (memcmp(x, vectors[i].digest, sizeof(vectors[i].digest))) {
      fprintf(stderr, "sha1() failed for test vector %u\n", i);
      return 1;
    }
  }

  return 0;
}
