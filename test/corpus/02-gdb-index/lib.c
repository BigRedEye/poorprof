#include "../util.h"

NOINLINE void f4() {
    SUSPEND
}

INLINE void f3() {
    f4();
    f4();
}

INLINE void f2() {
    f3();
    f3();
}

INLINE void f1() {
    f2();
    f2();
}

NOINLINE void foo() {
    f1();
    f1();
}
