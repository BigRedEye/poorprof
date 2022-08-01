# - Try to find libdebuginfod
# Once done this will define
#
#  LIBDEBUGINFOD_FOUND - system has libdebuginfod
#  LIBDEBUGINFOD_INCLUDE_DIRS - the libdebuginfod include directory
#  LIBDEBUGINFOD_LIBRARIES - Link these to use libdebuginfod
#  LIBDEBUGINFOD_DEFINITIONS - Compiler switches required for using libdebuginfod
#

find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
    set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)
    pkg_check_modules(PC_LIBDEBUGINFOD QUIET libdebuginfod)
endif()

find_path (LIBDEBUGINFOD_INCLUDE_DIR
    NAMES
        debuginfod.h
    HINTS
        ${PC_LIBDEBUGINFOD_INCLUDE_DIRS}
    PATHS
        /usr/include
        /usr/include/elfutils
        /usr/local/include
        /usr/local/include/elfutils
        /opt/local/include
        /opt/local/include/elfutils
        /sw/include
        /sw/include/elfutils
    ENV CPATH)

find_library (LIBDEBUGINFOD_LIBRARY
    NAMES
        debuginfod
    HINTS
        ${PC_LIBDEBUGINFOD_LIBRARY_DIRS}
    PATHS
        /usr/lib
        /usr/local/lib
        /opt/local/lib
        /sw/lib
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

# Transitive deps
find_package(CURL)

include (FindPackageHandleStandardArgs)

find_package_handle_standard_args(LibDebugInfoD DEFAULT_MSG
    LIBDEBUGINFOD_LIBRARY
    LIBDEBUGINFOD_INCLUDE_DIR
    CURL_LIBRARIES)


mark_as_advanced(LIBDEBUGINFOD_LIBRARY LIBDEBUGINFOD_INCLUDE_DIR)

set(LIBDEBUGINFOD_LIBRARIES ${LIBDEBUGINFOD_LIBRARY} ${CURL_LIBRARIES})
set(LIBDEBUGINFOD_INCLUDE_DIRS ${LIBDEBUGINFOD_INCLUDE_DIR} )
