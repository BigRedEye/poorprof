set(
    SOURCES
    main.cpp
)

set(
    HEADERS
)

add_executable(poorprof ${SOURCES} ${HEADERS})

target_link_libraries(poorprof
    PRIVATE ${POORPROF_PRIVATE_LIBRARIES} poorprof_util poorprof_dw
    PUBLIC ${POORPROF_PUBLIC_LIBRARIES}
)

if (${POORPROF_STATIC_LIBSTDCXX})
    target_link_options(poorprof PRIVATE -static-libgcc -static-libstdc++)
endif ()
if (${POORPROF_STATIC_LIBC})
    target_link_options(poorprof PRIVATE -static)
endif ()
