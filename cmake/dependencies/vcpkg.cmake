# Find required packages
find_package(fmt REQUIRED)
list(APPEND POORPROF_PRIVATE_LIBRARIES fmt::fmt)

find_package(elfutils REQUIRED)
list(APPEND POORPROF_PRIVATE_LIBRARIES elfutils::elfutils)
set(POORPROF_LIBRARY_ELFUTILS elfutils::elfutils)
