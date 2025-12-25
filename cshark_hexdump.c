//#########LLM GENERATED CODE BEGINS#########
#include "headers.h"

void print_hex_ascii(const u_char *data, int len) {
    int i, j;
    
    // Process 16 bytes per line
    for (i = 0; i < len; i += 16) {
        // Print offset
        printf("    ");
        
        // Print hex bytes
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");  // Fill space for incomplete lines
            }
        }
        
        // Add separator between hex and ASCII
        printf(" ");
        
        // Print ASCII representation
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                u_char c = data[i + j];
                // Print only printable ASCII characters
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            } else {
                printf(" ");  // Fill space for incomplete lines
            }
        }
        
        printf("\n");
    }
}
//#########LLM GENERATED CODE ENDS#########