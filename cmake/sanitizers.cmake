if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    SET(CMAKE_CXX_FLAGS_SANITIZERS "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address,undefined -fsanitize-undefined-trap-on-error"
        CACHE STRING "Flags for C++ with UBSan and ASan enabled."
        FORCE)
    SET(CMAKE_C_FLAGS_SANITIZERS "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address,undefined -fsanitize-undefined-trap-on-error"
        CACHE STRING "Flags for C with UBSan and ASan enabled."
        FORCE)
    SET(CMAKE_EXE_LINKER_FLAGS_SANITIZERS
        "${CMAKE_EXE_LINKER_FLAGS_DEBUG}" CACHE STRING
        "Flags for linker with UBSan and ASan enabled."
        FORCE)
    SET(CMAKE_SHARED_LINKER_FLAGS_SANITIZERS
        "${CMAKE_SHARED_LINKER_FLAGS_DEBUG}" CACHE STRING
        "Flags for linker with UBSan and ASan enabled."
        FORCE)
    MARK_AS_ADVANCED(
        CMAKE_CXX_FLAGS_SANITIZERS
        CMAKE_C_FLAGS_SANITIZERS
        CMAKE_EXE_LINKER_FLAGS_SANITIZERS
        CMAKE_SHARED_LINKER_FLAGS_SANITIZERS)

    SET(CMAKE_BUILD_TYPE "${CMAKE_BUILD_TYPE}" CACHE STRING
        "Choose the type of build, options are: None Debug Release RelWithDebInfo MinSizeRel Sanitizers."
        FORCE)
endif()
