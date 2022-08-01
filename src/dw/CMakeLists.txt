set(
    SOURCES
    debuginfod.cpp
    dw.cpp
)

set(
    HEADERS
    debuginfod.h
    dw.h
)

add_library(poorprof_dw ${SOURCES} ${HEADERS})
set_target_properties(poorprof_dw PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(poorprof_dw
    PUBLIC ${LIBDWARF_LIBRARIES} ${LIBDEBUGINFOD_LIBRARIES}
    PUBLIC ${CMAKE_DL_LIBS}
)

target_include_directories(poorprof_dw
    PUBLIC ${LIBDWARF_INCLUDE_DIRS}
)
