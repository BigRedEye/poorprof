if(NOT EXISTS "${CMAKE_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "http://raw.githubusercontent.com/conan-io/cmake-conan/v0.16.1/conan.cmake"
        "${CMAKE_BINARY_DIR}/conan.cmake"
        EXPECTED_HASH SHA256=396e16d0f5eabdc6a14afddbcfff62a54a7ee75c6da23f32f7a31bc85db23484
        TLS_VERIFY OFF)
endif()

include(${CMAKE_BINARY_DIR}/conan.cmake)

conan_cmake_autodetect(settings)

conan_cmake_install(
    PATH_OR_REFERENCE ${CMAKE_SOURCE_DIR}/conanfile.py
    BUILD all
    SETTINGS ${settings}
)

include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
conan_basic_setup(TARGETS)

list(APPEND POORPROF_PRIVATE_LIBRARIES CONAN_PKG::fmt)
list(APPEND POORPROF_PRIVATE_LIBRARIES CONAN_PKG::spdlog)
list(APPEND POORPROF_PRIVATE_LIBRARIES CONAN_PKG::elfutils)
list(APPEND POORPROF_PRIVATE_LIBRARIES CONAN_PKG::abseil)
set(POORPROF_LIBRARY_ELFUTILS CONAN_PKG::elfutils)
