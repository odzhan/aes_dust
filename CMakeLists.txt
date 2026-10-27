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
option(AES_DUST_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(AES_DUST_TEST_DIFFERENTIAL "Run Python reference-library and Wycheproof tests (requires shared library)" OFF)

if(AES_DUST_ENABLE_SANITIZERS AND AES_DUST_TEST_DIFFERENTIAL)
    message(FATAL_ERROR "Use separate sanitizer and differential build directories; Python cannot normally load an ASan-instrumented library")
endif()

if(AES_DUST_ENABLE_SANITIZERS)
    if(MSVC OR NOT CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        message(FATAL_ERROR "AES_DUST_ENABLE_SANITIZERS requires GCC or Clang with ASan/UBSan support")
    endif()
    add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
endif()

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

# Treat Windows shared libs without explicit exports more leniently
if(WIN32 AND BUILD_SHARED_LIBS)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

# Enable CTest and the BUILD_TESTING option
include(CTest)
include(GNUInstallDirs)

# Library lives under src/
add_subdirectory(src)

# MinGW defaults to legacy CRT printf without C99 size_t formatting.
if(MINGW)
    add_compile_definitions(__USE_MINGW_ANSI_STDIO=1)
endif()

# Tests (only when requested)
if(BUILD_TESTING)
    add_executable(aes_dust_test tests/test.c)
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

    add_executable(aes_dust_lightmac_test tests/test_lightmac.c)
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
    # Includes the legitimate 8-bit tag collision at deterministic iteration 4251.
    add_test(NAME aes_dust_lightmac_fuzz COMMAND aes_dust_lightmac_test fuzz 5000)

    add_executable(aes_dust_vectors_test tests/test_vectors.c)
    target_link_libraries(aes_dust_vectors_test PRIVATE aes_dust::aes128)
    target_compile_definitions(aes_dust_vectors_test PRIVATE $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>)
    if(MSVC)
        target_compile_options(aes_dust_vectors_test PRIVATE /W4)
        if(AES_DUST_ENABLE_WERROR)
            target_compile_options(aes_dust_vectors_test PRIVATE /WX)
        endif()
    else()
        target_compile_options(aes_dust_vectors_test PRIVATE -Wall -Wextra -Wpedantic)
        if(AES_DUST_ENABLE_WERROR)
            target_compile_options(aes_dust_vectors_test PRIVATE -Werror)
        endif()
    endif()
    add_test(NAME aes_dust_vectors_test COMMAND aes_dust_vectors_test)

    foreach(suite aead modes)
        add_executable(aes_dust_${suite}_test tests/test_${suite}.c)
        target_link_libraries(aes_dust_${suite}_test PRIVATE aes_dust::aes128)
        if(MSVC)
            target_compile_options(aes_dust_${suite}_test PRIVATE /W4)
            if(AES_DUST_ENABLE_WERROR)
                target_compile_options(aes_dust_${suite}_test PRIVATE /WX)
            endif()
        else()
            target_compile_options(aes_dust_${suite}_test PRIVATE -Wall -Wextra -Wpedantic)
            if(AES_DUST_ENABLE_WERROR)
                target_compile_options(aes_dust_${suite}_test PRIVATE -Werror)
            endif()
        endif()
        add_test(NAME aes_dust_${suite}_test COMMAND aes_dust_${suite}_test)
    endforeach()

    if(AES_DUST_TEST_DIFFERENTIAL)
        if(NOT BUILD_SHARED_LIBS)
            message(FATAL_ERROR "AES_DUST_TEST_DIFFERENTIAL requires BUILD_SHARED_LIBS=ON")
        endif()
        find_package(Python3 3.9 REQUIRED COMPONENTS Interpreter)
        add_test(NAME aes_dust_differential
            COMMAND "${Python3_EXECUTABLE}" "${PROJECT_SOURCE_DIR}/tests/differential.py"
                    --library "$<TARGET_FILE:aes128>")
        set_tests_properties(aes_dust_differential PROPERTIES TIMEOUT 180)
    endif()

    function(aes_dust_add_compact_test name key_bytes int_bytes sbox_mode)
        add_executable(${name} src/compact/test128.c src/compact/aes.c)
        target_include_directories(${name} PRIVATE src/compact)
        target_compile_features(${name} PRIVATE c_std_99)
        target_compile_definitions(${name} PRIVATE
            AES_KEY_LEN=${key_bytes} AES_INT_LEN=${int_bytes} CTR OFB
            $<$<C_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>)
        if(NOT sbox_mode STREQUAL "STATIC")
            target_compile_definitions(${name} PRIVATE ${sbox_mode})
        endif()
        if(MSVC)
            target_compile_options(${name} PRIVATE /W4)
            if(AES_DUST_ENABLE_WERROR)
                target_compile_options(${name} PRIVATE /WX)
            endif()
        else()
            target_compile_options(${name} PRIVATE -Wall -Wextra -Wpedantic)
            if(AES_DUST_ENABLE_WERROR)
                target_compile_options(${name} PRIVATE -Werror)
            endif()
        endif()
        add_test(NAME ${name} COMMAND ${name})
    endfunction()

    foreach(sbox_mode STATIC DYNAMIC RUNTIME)
        string(TOLOWER "${sbox_mode}" sbox_name)
        aes_dust_add_compact_test(aes_dust_compact_128_${sbox_name}_test 16 4 ${sbox_mode})
        aes_dust_add_compact_test(aes_dust_compact_128_8_${sbox_name}_test 16 1 ${sbox_mode})
        aes_dust_add_compact_test(aes_dust_compact_256_${sbox_name}_test 32 4 ${sbox_mode})
    endforeach()

endif()

if(AES_DUST_TEST_DIFFERENTIAL AND NOT BUILD_TESTING)
    message(FATAL_ERROR "AES_DUST_TEST_DIFFERENTIAL requires BUILD_TESTING=ON")
endif()

# Install rules and CMake package config
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
# Resolve the prefix from the installed .pc file so --install --prefix and
# moving an installation tree both work with relative installation directories.
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    # An absolute library directory does not follow --install --prefix, so
    # pcfiledir cannot locate the prefix. Refresh it at installation time.
    set(AES_DUST_PC_PREFIX "${CMAKE_INSTALL_PREFIX}")
else()
    file(RELATIVE_PATH AES_DUST_PC_PREFIX_RELATIVE
        "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig" "${CMAKE_INSTALL_PREFIX}")
    set(AES_DUST_PC_PREFIX "\${pcfiledir}/${AES_DUST_PC_PREFIX_RELATIVE}")
endif()
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    set(AES_DUST_PC_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
else()
    set(AES_DUST_PC_LIBDIR "\${prefix}/${CMAKE_INSTALL_LIBDIR}")
endif()
if(IS_ABSOLUTE "${CMAKE_INSTALL_INCLUDEDIR}")
    set(AES_DUST_PC_INCLUDEDIR "${CMAKE_INSTALL_INCLUDEDIR}")
else()
    set(AES_DUST_PC_INCLUDEDIR "\${prefix}/${CMAKE_INSTALL_INCLUDEDIR}")
endif()
configure_file(pkgconfig/aes_dust.pc.in ${CMAKE_CURRENT_BINARY_DIR}/aes_dust.pc @ONLY)
if(IS_ABSOLUTE "${CMAKE_INSTALL_LIBDIR}")
    # Keep a build-tree copy of the template: installation need not retain
    # access to the source tree. DESTDIR belongs only to the copy operation,
    # not to paths embedded in the installed metadata.
    configure_file(pkgconfig/aes_dust.pc.in ${CMAKE_CURRENT_BINARY_DIR}/aes_dust.pc.in COPYONLY)
    string(CONFIGURE [=[
        set(AES_DUST_PC_PREFIX "${CMAKE_INSTALL_PREFIX}")
        set(AES_DUST_PC_LIBDIR [==[@AES_DUST_PC_LIBDIR@]==])
        set(AES_DUST_PC_INCLUDEDIR [==[@AES_DUST_PC_INCLUDEDIR@]==])
        set(PROJECT_VERSION "@PROJECT_VERSION@")
        configure_file("@CMAKE_CURRENT_BINARY_DIR@/aes_dust.pc.in"
                       "@CMAKE_CURRENT_BINARY_DIR@/aes_dust.pc" @ONLY)
    ]=] AES_DUST_PC_INSTALL_CODE @ONLY)
    install(CODE "${AES_DUST_PC_INSTALL_CODE}")
endif()
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/aes_dust.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
