set(SOURCES
    align.cpp
    backward.cpp
    ctrlc.cpp
    demangle.cpp
)
set(HEADERS
)

add_library(poorprof_util OBJECT ${SOURCES} ${HEADERS})

target_link_libraries(poorprof_util
    PRIVATE backward ${LIBDW_LIBRARIES}
    PUBLIC
)

target_include_directories(poorprof_util
    PRIVATE ${LIBDW_INCLUDE_DIRS}
)
