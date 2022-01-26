include(FetchContent)


### threads ###
find_package(Threads REQUIRED)
list(APPEND POORPROF_PUBLIC_LIBRARIES Threads::Threads)


### cpparg ###
FetchContent_Declare(
    cpparg
    GIT_REPOSITORY https://github.com/BigRedEye/cpparg
    GIT_TAG        v0.2.3
)

if(NOT cpparg_POPULATED)
    FetchContent_Populate(cpparg)
    add_subdirectory(${cpparg_SOURCE_DIR} ${cpparg_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
list(APPEND POORPROF_PRIVATE_LIBRARIES cpparg::cpparg)


### backward-cpp ###
if (POORPROF_ENABLE_BACKWARD)
    FetchContent_Declare(
        backward
        GIT_REPOSITORY https://github.com/bombela/backward-cpp
        GIT_TAG        5ffb2c879ebdbea3bdb8477c671e32b1c984beaa
    )

    if(NOT backward_POPULATED)
        FetchContent_Populate(backward)
        add_definitions(-DBACKWARD_HAS_DW=1)
        add_subdirectory(${backward_SOURCE_DIR} ${backward_BINARY_DIR} EXCLUDE_FROM_ALL)
    endif()
    list(APPEND POORPROF_PRIVATE_LIBRARIES backward backward_object)
endif()
