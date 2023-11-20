#include <string.h>
#include <stdio.h>
#include "aes.h"
#include "aes-mmo.h"

#include <stdlib.h>


void hex_string_to_byte_array(const char *hex_string, unsigned char *byte_array, int byte_array_length) {
    for (int i = 0; i < byte_array_length; i++) {
        sscanf(&hex_string[i*2], "%2hhx", &byte_array[i]);
    }
}

int main() {
char* installCode = "A87710C3E5C332E5327EE532C3C310E5DFE0"; // install code of the zigbee device
    int length = strlen(installCode) / 2; // Each byte is represented by 2 hex characters
    unsigned char* message = malloc(length);
    hex_string_to_byte_array(installCode, message, length);
    char digest[16];
    aes_mmo(digest, message, length);

    for (int i = 0; i < 16; i++) {
        printf("%02x", (unsigned char)digest[i]);
    }
    printf("\n");

    free(message);
    return 0;
}








