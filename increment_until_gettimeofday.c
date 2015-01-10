#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <unistd.h>

#include "entropy_source.h"

void gettimeofday_or_die(struct timeval* tv) {
    if (gettimeofday(tv, NULL) < 0) {
        perror("gettimeofday failed");
        exit(2);
    }
}

suseconds_t timevaldiff(
    struct timeval const* starttime,
    struct timeval const* finishtime
) {
    suseconds_t diff = finishtime->tv_usec - starttime->tv_usec;
    diff += 1000000 * (finishtime->tv_sec - starttime->tv_sec);
    return diff;
}

uint8_t get_random_byte() {
    struct timeval now, then;
    uint8_t cycles;

    // this is *intentionally* a slow clock
    gettimeofday_or_die(&then);

    while (1) {
        ++cycles;
    	gettimeofday_or_die(&now);
    	
        if (timevaldiff(&then, &now) > 100) { break; }
    }

    return cycles;
}
