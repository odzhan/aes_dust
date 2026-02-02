add_library(aes128
    aes128_ecb.c
    aes128_cbc.c
    aes128_cfb.c
    aes128_ctr.c
    aes128_ccm.c
    aes128_eax.c
    aes128_gcm.c
    aes128_gcm_siv.c
    aes128_ofb.c
    aes128_lightmac.c
    aes128_xts.c
)

add_library(aes_dust::aes128 ALIAS aes128)

# Public headers live in the top-level include/ directory
target_include_directories(aes128
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(aes128 PUBLIC c_std_99)

set_target_properties(aes128 PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    OUTPUT_NAME aes128
)

if(MSVC)
    target_compile_options(aes128 PRIVATE /W4)
else()
    target_compile_options(aes128 PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(AES_DUST_ENABLE_WERROR)
    if(MSVC)
        target_compile_options(aes128 PRIVATE /WX)
    else()
        target_compile_options(aes128 PRIVATE -Werror)
    endif()
endif()
