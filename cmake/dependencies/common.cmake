include(FetchContent)

### cpparg ###

FetchContent_Declare(
    cpparg
    GIT_REPOSITORY https://github.com/BigRedEye/cpparg
    GIT_TAG        v0.2.3
)

if(NOT cpparg_POPULATED)
  FetchContent_Populate(cpparg)

  # Bring the populated content into the build
  add_subdirectory(${cpparg_SOURCE_DIR} ${cpparg_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

list(APPEND POORPROF_PRIVATE_LIBRARIES cpparg::cpparg)

### threads ###
find_package(Threads REQUIRED)
list(APPEND POORPROF_PUBLIC_LIBRARIES Threads::Threads)
