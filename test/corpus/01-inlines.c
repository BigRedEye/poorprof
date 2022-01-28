#include "util.h"

NOINLINE void f5() {
    SUSPEND;
}

NOINLINE void f4() {
    f5();
}

NOINLINE void f3() {
    f4();
}

INLINE void f2inline() {
    f3();
}

INLINE void f1inline() {
    f2inline();
}

INLINE void f0inline() {
    f1inline();
}

NOINLINE void _start() {
    f0inline();
}
