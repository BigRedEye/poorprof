# - Try to find libdwarf
# Once done this will define
#
#  LIBDW_FOUND - system has libdwarf
#  LIBDW_INCLUDE_DIRS - the libdwarf include directory
#  LIBDW_LIBRARIES - Link these to use libdwarf
#  LIBDW_DEFINITIONS - Compiler switches required for using libdwarf
#

# Locate libelf library at first
if (NOT LIBELF_FOUND)
   find_package (LibElf)
endif (NOT LIBELF_FOUND)

find_package(PkgConfig QUIET)

if(PKG_CONFIG_FOUND)
  set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)
  pkg_check_modules(PC_LIBDW QUIET libdw)
endif()

find_path (DWARF_INCLUDE_DIR
    NAMES
      dwarf.h
    HINTS
      ${PC_LIBDW_INCLUDE_DIRS}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ENV CPATH) # PATH and INCLUDE will also work
find_path (LIBDW_INCLUDE_DIR
    NAMES
      elfutils/libdw.h
    HINTS
      ${PC_LIBDW_INCLUDE_DIRS}
    PATHS
      /usr/include
      /usr/local/include
      /opt/local/include
      /sw/include
      ENV CPATH)
if (DWARF_INCLUDE_DIR AND LIBDW_INCLUDE_DIR)
    set (LIBDWARF_INCLUDE_DIRS  ${DWARF_INCLUDE_DIR} ${LIBDW_INCLUDE_DIR})
endif (DWARF_INCLUDE_DIR AND LIBDW_INCLUDE_DIR)

find_library (LIBDW_LIBRARY
    NAMES
      dw
    HINTS
      ${PC_LIBDW_LIBRARY_DIRS}
    PATHS
      /usr/lib
      /usr/local/lib
      /opt/local/lib
      /sw/lib
      ENV LIBRARY_PATH   # PATH and LIB will also work
      ENV LD_LIBRARY_PATH)


find_package(Threads QUIET)
find_library(LIBBZ2_LIBRARY bz2)
find_library(LIBLZMA_LIBRARY lzma)
find_library(LIBZSTD_LIBRARY zstd)

include (FindPackageHandleStandardArgs)


# handle the QUIETLY and REQUIRED arguments and set LIBDWARF_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(ElfUtils DEFAULT_MSG
    LIBDW_LIBRARY
    LIBDW_INCLUDE_DIR)

mark_as_advanced(LIBDW_INCLUDE_DIR LIBDW_LIBRARY)

set(LIBDW_LIBRARIES ${LIBDW_LIBRARY} ${LIBELF_LIBRARIES}
    $<$<BOOL:${LIBBZ2_LIBRARY}>:${LIBBZ2_LIBRARY}>
    $<$<BOOL:${LIBLZMA_LIBRARY}>:${LIBLZMA_LIBRARY}>
    $<$<BOOL:${LIBZSTD_LIBRARY}>:${LIBZSTD_LIBRARY}>
)
if (Threads_FOUND)
    list(APPEND LIBDW_LIBRARIES Threads::Threads)
endif ()

set(LIBDW_INCLUDE_DIRS ${LIBDW_INCLUDE_DIR} ${LIBELF_INCLUDE_DIRS})
