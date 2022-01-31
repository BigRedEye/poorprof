message("CMAKE_TOOLCHAIN_FILE is set to ${CMAKE_TOOLCHAIN_FILE}")
if (CMAKE_TOOLCHAIN_FILE)
    message("CMAKE_TOOLCHAIN_FILE is set to ${CMAKE_TOOLCHAIN_FILE}")
else()
    include(FetchContent)

    FetchContent_Declare(
        vcpkg
        GIT_REPOSITORY https://github.com/microsoft/vcpkg
        GIT_TAG        master
    )

    FetchContent_GetProperties(vcpkg)
    if(NOT vcpkg_POPULATED)
        message("Downloading vcpkg")
        FetchContent_Populate(vcpkg)
    endif()

    # Use vcpkg toolchain file in order to use FindPackage
    FetchContent_GetProperties(vcpkg SOURCE_DIR vcpkg_source_dir INSTALL_DIR vcpkg_install_dir)
    set(CMAKE_TOOLCHAIN_FILE ${vcpkg_source_dir}/scripts/buildsystems/vcpkg.cmake CACHE STRING "Vcpkg toolchain file")
endif()
