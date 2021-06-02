find_package(Freetype REQUIRED)
list(APPEND POORPROF_PRIVATE_LIBRARIES Freetype::Freetype)

find_package(harfbuzz REQUIRED)
list(APPEND POORPROF_PRIVATE_LIBRARIES harfbuzz::harfbuzz)

find_package(Fontconfig REQUIRED)
list(APPEND POORPROF_PRIVATE_LIBRARIES Fontconfig::Fontconfig)
