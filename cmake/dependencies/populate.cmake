include(cmake/dependencies/common.cmake)

if(${POORPROF_DEPS} STREQUAL "system")
    include(cmake/dependencies/system.cmake)
elseif(${POORPROF_DEPS} STREQUAL "vcpkg")
    include(cmake/dependencies/vcpkg.cmake)
else()
    message(FATAL "Unknown dependencies provider ${POORPROF_DEPS}")
endif()
