set(
    SOURCES
    main.cpp
)

set(
    HEADERS
)

add_executable(poorprof ${SOURCES} ${HEADERS})
set_target_properties(poorprof PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(poorprof
    PRIVATE ${POORPROF_PRIVATE_LIBRARIES} poorprof_dw
    PUBLIC ${POORPROF_PUBLIC_LIBRARIES}
)

if (${POORPROF_STATIC_LIBSTDCXX})
    target_link_options(poorprof PRIVATE -static-libgcc -static-libstdc++)
endif ()
if (${POORPROF_STATIC_LIBC})
    target_link_options(poorprof PRIVATE -static)
endif ()
