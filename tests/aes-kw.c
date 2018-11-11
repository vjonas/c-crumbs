/*
 * tests/aes-kw.c: tests for ../aes-kw.h
 *
 * https://github.com/andrebdo/c-crumbs/blob/master/tests/aes-kw.c
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

#include "../aes.h"
#include "../aes-kw.h"
#include <stdio.h>
#include <string.h>

/*
 * Tests the aes_kw function with the example values in RFC3394:
 * Test Vectors 4.1 Wrap 128 bits of Key Data with a 128-bit KEK.
 */
int main(int argc, char **argv) {
  const unsigned char key[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
  };
  const unsigned char plaintext[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  const unsigned char ciphertext[8 + sizeof(plaintext)] = {
    0x1f, 0xa6, 0x8b, 0x0a, 0x81, 0x12, 0xb4, 0x47,
    0xae, 0xf3, 0x4b, 0xd8, 0xfb, 0x5a, 0x7b, 0x82,
    0x9d, 0x3e, 0x86, 0x23, 0x71, 0xd2, 0xcf, 0xe5
  };
  unsigned char x[sizeof(ciphertext)];

  aes_kw(x, plaintext, sizeof(plaintext) / 8, key);
  if (memcmp(x, ciphertext, sizeof(ciphertext))) {
    fputs("aes_kw() failed\n", stderr);
    return 1;
  }

  return 0;
}
