#include "../util.h"

NOINLINE void foo();

NOINLINE void bar() {
    foo();
}

void _start() {
    bar();
}
