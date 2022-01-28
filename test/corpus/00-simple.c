#include "util.h"

NOINLINE void foo() {
    SUSPEND;
}

NOINLINE void bar() {
    foo();
    foo();
}

NOINLINE void _start() {
    bar();
    bar();
}
