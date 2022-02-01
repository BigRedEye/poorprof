#include "../util.h"

#include <unistd.h>
#include <time.h>

void NOINLINE Foo() {
    while (1) {
        struct timespec remaining;
        nanosleep(&(struct timespec){
            .tv_sec = 1000,
            .tv_nsec = 0,
        }, &remaining);
    }
}

void NOINLINE Bar() {
    Foo();
}

int main() {
    Bar();
}
