# poorprof
[![Build](https://github.com/BigRedEye/poorprof/actions/workflows/docker.yml/badge.svg)](https://github.com/BigRedEye/poorprof/actions/workflows/docker.yml)

Simple and fast [poor man's profiler](https://poormansprofiler.org/) for Linux.

## Build
Requires CMake and GCC with decent support of C++20 features (GCC 11). Clang support will be added later (it is blocked by some dependencies).
```
cmake --preset release-vcpkg
cmake --build --preset release-vcpkg --parallel
```

There are fully static nightly [builds](https://github.com/BigRedEye/poorprof/releases/tag/latest) that can be used on any Linux distribution.

## Use
```
./build/release-vcpkg/bin/poorprof --help
```
