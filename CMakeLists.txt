cmake_minimum_required(VERSION 3.16)

project(aes_dust
    VERSION 1.0.0
    DESCRIPTION "Compact AES-128 block cipher library"
    LANGUAGES C
)

# Export compile_commands.json (useful for IDEs and tooling)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Core build options
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(AES_DUST_ENABLE_WERROR "Treat warnings as errors" OFF)

# Default build type only for single-config generators
# Do not override user-provided or multi-config (e.g. MSVC) settings.
if(NOT CMAKE_CONFIGURATION_TYPES)
    if(NOT CMAKE_BUILD_TYPE)
        set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
        set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "RelWithDebInfo" "MinSizeRel")
    endif()
endif()

# Output directories for artifacts
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_SUPPRESS_REGENERATION ON)

# Treat Windows shared libs without explicit exports more leniently
if(WIN32 AND BUILD_SHARED_LIBS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Enable CTest and the BUILD_TESTING option
include(CTest)

# Library lives under src/
add_subdirectory(src)

# Tests (only when requested)
if(BUILD_TESTING)
    add_executable(aes_dust_test test.c)
    target_link_libraries(aes_dust_test PRIVATE aes_dust::aes128)
    target_compile_definitions(aes_dust_test PRIVATE $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>)
    if(MSVC)
        target_compile_options(aes_dust_test PRIVATE /W4)
        if(AES_DUST_ENABLE_WERROR)
            target_compile_options(aes_dust_test PRIVATE /WX)
        endif()
    else()
        target_compile_options(aes_dust_test PRIVATE -Wall -Wextra -Wpedantic)
        if(AES_DUST_ENABLE_WERROR)
            target_compile_options(aes_dust_test PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME aes_dust_test COMMAND aes_dust_test)

    add_executable(aes_dust_lightmac_test test_lightmac.c)
    target_link_libraries(aes_dust_lightmac_test PRIVATE aes_dust::aes128)
    target_compile_definitions(aes_dust_lightmac_test PRIVATE $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>)
    if(MSVC)
        target_compile_options(aes_dust_lightmac_test PRIVATE /W4)
        if(AES_DUST_ENABLE_WERROR)
            target_compile_options(aes_dust_lightmac_test PRIVATE /WX)
        endif()
    else()
        target_compile_options(aes_dust_lightmac_test PRIVATE -Wall -Wextra -Wpedantic)
        if(AES_DUST_ENABLE_WERROR)
            target_compile_options(aes_dust_lightmac_test PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME aes_dust_lightmac_kat COMMAND aes_dust_lightmac_test kat)
    add_test(NAME aes_dust_lightmac_fuzz COMMAND aes_dust_lightmac_test fuzz 200)
endif()

# Install rules and CMake package config
include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

set(INSTALL_CONFIGDIR ${CMAKE_INSTALL_LIBDIR}/cmake/aes_dust)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(TARGETS aes128
        EXPORT aes_dustTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

# Generate and install the package configuration files
configure_package_config_file(
    cmake/aes_dustConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/aes_dustConfig.cmake
    INSTALL_DESTINATION ${INSTALL_CONFIGDIR}
)

write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/aes_dustConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(EXPORT aes_dustTargets
        FILE aes_dustTargets.cmake
        NAMESPACE aes_dust::
        DESTINATION ${INSTALL_CONFIGDIR})

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/aes_dustConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/aes_dustConfigVersion.cmake
    DESTINATION ${INSTALL_CONFIGDIR}
)

# Optional pkg-config file
configure_file(pkgconfig/aes_dust.pc.in ${CMAKE_CURRENT_BINARY_DIR}/aes_dust.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/aes_dust.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
