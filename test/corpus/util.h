#pragma once

#define NOINLINE __attribute__((noinline))
#define INLINE __attribute__((always_inline))
#define SUSPEND for (volatile int kek = 0; kek == 0; /*pass*/) {}
