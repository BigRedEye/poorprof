set(POORPROF_UNWIND_PROVIDER "libdwfl;libunwind" CACHE STRING "Which unwinders to use: libdwfl, libunwind or libunwind-llvm")
set(POORPROF_DEBUG_INFO_PROVIDER "libdwfl" CACHE STRING "Which debug info parser to use: libdwfl")

set(POORPROF_STATIC_LIBSTDCXX FALSE CACHE BOOL "Enable -static-libgcc -static-libstdc++")
set(POORPROF_STATIC_LIBC FALSE CACHE BOOL "Enable -static")
