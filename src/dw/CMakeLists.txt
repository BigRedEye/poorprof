set(
    SOURCES
    dw.cpp
)

set(
    HEADERS
    dw.h
)

add_library(poorprof_dw ${SOURCES} ${HEADERS})
set_target_properties(poorprof_dw PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(poorprof_dw
    PRIVATE ${POORPROF_LIBRARY_ELFUTILS}
    PUBLIC ${CMAKE_DL_LIBS}
)
