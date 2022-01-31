# poorprof
Simple and fast [poor man's profiler](https://poormansprofiler.org/) for Linux.

## Build
Requires CMake and GCC with decent support of C++20 features (GCC 11). Clang support will be added later (it is blocked by some dependencies).
```
cmake --preset release-vcpkg
cmake --build --preset release-vcpkg --parallel
```

## Use
```
./build/release-vcpkg/bin/poorprof --help
```
