message("Using ${POORPROF_UNWIND_PROVIDER} unwind providers")
message("Using ${POORPROF_DEBUG_INFO_PROVIDER} debug info providers")

if (FALSE)
    if ("libunwind-llvm" IN_LIST POORPROF_UNWIND_PROVIDER)
        list(APPEND VCPKG_MANIFEST_FEATURES "libunwind-llvm")
    endif()

    if ("libdwfl" IN_LIST POORPROF_UNWIND_PROVIDER)
        list(APPEND VCPKG_MANIFEST_FEATURES "libdwfl")
    endif()

    if ("libdwfl" IN_LIST POORPROF_DEBUG_INFO_PROVIDER)
        list(APPEND VCPKG_MANIFEST_FEATURES "libdwfl")
    endif()
endif()
