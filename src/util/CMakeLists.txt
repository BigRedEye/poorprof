set(SOURCES
    backward.cpp
)
set(HEADERS
)

add_library(poorprof_util OBJECT ${SOURCES} ${HEADERS})

target_link_libraries(poorprof_util
    PRIVATE backward
    PUBLIC
)
