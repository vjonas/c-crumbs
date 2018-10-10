/*
 * base64.h: base 64 data encoding
 *
 * https://github.com/andrebdo/c-crumbs/base64.h
 *
 * This is free and unencumbered software released into the public domain.
 * For more information, please refer to UNLICENSE or http://unlicense.org
 */

/*
 * Encodes a sequence of bytes into base 64 format.
 * output: pointer to (length+2)/3*4 bytes of memory to store the base 64 encoded data
 * input: pointer to the input data
 * length: number of bytes of the input data
 * Returns the number of bytes stored in output, always (length+2)/3*4.
 *
 * References:
 * [RFC4648] The Base16, Base32, and Base64 Data Encodings.
 */
static int base64_encode(void *output, const void *input, int length) {
  const char alphabet[64] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M',
    'N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m',
    'n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9','+','/',
  };
  unsigned char a, b, c;
  int i, n;

  n = 0;
  for (i = 0; i <= length - 3; i += 3) {
    a = ((unsigned char *)input)[i];
    b = ((unsigned char *)input)[i + 1];
    c = ((unsigned char *)input)[i + 2];
    ((unsigned char *)output)[n++] = alphabet[(a >> 2) & 63];
    ((unsigned char *)output)[n++] = alphabet[(a << 4 | b >> 4) & 63];
    ((unsigned char *)output)[n++] = alphabet[(b << 2 | c >> 6) & 63];
    ((unsigned char *)output)[n++] = alphabet[c & 63];
  }
  if (i + 2 == length) {
    a = ((unsigned char *)input)[i];
    b = ((unsigned char *)input)[i + 1];
    ((unsigned char *)output)[n++] = alphabet[(a >> 2) & 63];
    ((unsigned char *)output)[n++] = alphabet[(a << 4 | b >> 4) & 63];
    ((unsigned char *)output)[n++] = alphabet[(b << 2) & 63];
    ((unsigned char *)output)[n++] = '=';
  } else if (i + 1 == length) {
    a = ((unsigned char *)input)[i];
    ((unsigned char *)output)[n++] = alphabet[(a >> 2) & 63];
    ((unsigned char *)output)[n++] = alphabet[(a << 4) & 63];
    ((unsigned char *)output)[n++] = '=';
    ((unsigned char *)output)[n++] = '=';
  }

  return n;
}
