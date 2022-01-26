include(cmake/dependencies/common.cmake)

if(${POORPROF_DEPS} STREQUAL "system")
    include(cmake/dependencies/system.cmake)
elseif(${POORPROF_DEPS} STREQUAL "vcpkg")
    include(cmake/dependencies/vcpkg.cmake)
endif()
