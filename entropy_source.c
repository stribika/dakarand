#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "entropy_source.h"

void fread_or_die(void* ptr, size_t size, size_t nmemb, FILE* stream) {  
    if (fread(ptr, size, nmemb, stream) != nmemb) {
        perror("fread failed");
        exit(1);
    }
}

void fwrite_or_die(void const* ptr, size_t size, size_t nmemb, FILE* stream) {  
    if (fwrite(ptr, size, nmemb, stream) != nmemb) {
        perror("fwrite failed");
        exit(1);
    }
}

void fflush_or_die(FILE* stream) {  
    if (fflush(stream) < 0) {
        perror("fflush failed");
        exit(1);
    }
}

int main(int argc, char* argv[], char* env[]) {
    uint8_t n;
    
    do {
        fread_or_die(&n, sizeof(n), 1, stdin);
        
        for (uint16_t i = 0; i < n; ++i) {
            uint8_t const r = get_random_byte();
            fwrite_or_die(&r, sizeof(r), 1, stdout);
        }

        fflush_or_die(stdout);
    } while (n != 0);
    
    return 0;
}
