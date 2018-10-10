/*
 * tests/base64.c: tests for ../base64.h
 *
 * https://github.com/andrebdo/c-crumbs/tests/base64.c
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

#include "../base64.h"
#include <stdio.h>
#include <string.h>

/*
 * Tests the base64_encode function with the example values in
 * [RFC4648] The Base16, Base32, and Base64 Data Encodings.
 */
int main(int argc, char **argv) {
  const struct { char input[7]; char output[9]; } vectors[] = {
    /* [RFC4648] Section 9. Illustrations and Examples */
    { "\x14\xfb\x9c\x03\xd9\x7e", "FPucA9l+" },
    { "\x14\xfb\x9c\x03\xd9", "FPucA9k=" },
    { "\x14\xfb\x9c\x03", "FPucAw==" },
    /* [RFC4648] Section 10. Test Vectors */
    { "", "" },
    { "f", "Zg==" },
    { "fo", "Zm8=" },
    { "foo", "Zm9v" },
    { "foob", "Zm9vYg==" },
    { "fooba", "Zm9vYmE=" },
    { "foobar", "Zm9vYmFy" },
  };
  char output[sizeof(vectors[0].output)];
  unsigned i;

  for (i = 0; i < sizeof(vectors) / sizeof(vectors[0]); i++) {
    unsigned n = base64_encode(output, vectors[i].input, strlen(vectors[i].input));
    if (n != strlen(vectors[i].output)) {
      fprintf(stderr, "base64_encode() return value failed for test vector %u\n", i);
      return 1;
    }
    if (memcmp(output, vectors[i].output, n)) {
      fprintf(stderr, "base64_encode() output failed for test vector %u\n", i);
      return 1;
    }
  }

  return 0;
}
