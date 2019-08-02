cmake_minimum_required(VERSION 2.8)

project(hopper-emscripten)

set(CMAKE_VERBOSE_MAKEFILE on)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/build.emscripten)

set(USE_ASM OFF)
set(WITH_PROCPS OFF)
set(DEBUG OFF)
set(WITH_SUPERCOP OFF)
set(CMAKE_CXX_FLAGS "--std=c++11 -O3 -fno-rtti -s ALLOW_MEMORY_GROWTH=1 -s DISABLE_EXCEPTION_CATCHING=0")

set(CMAKE_PREFIX_PATH ${CMAKE_CURRENT_SOURCE_DIR}/installroot)

set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH on)

set(GMP_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/installroot/lib/libgmp.a)
set(GMP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/installroot/include)
set(GMP_LIBRARIES ${CMAKE_CURRENT_SOURCE_DIR}/installroot/lib/libgmp.a)



include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/installroot/include)

add_subdirectory(../ethsnarks ethsnarks-build)
add_subdirectory(../circuit/gadgets gadgets-build)


add_definitions(-DBINARY_OUTPUT -DCURVE_ALT_BN128 -DMONTGOMERY_OUTPUT -DNO_PROCPS -DNO_PT_COMPRESSION=1)

include_directories(../ethsnarks/src)
include_directories(
  ${DEPENDS_DIR}/json
  ../circuit/gadgets/SHA3IUF
  ${DEPENDS_DIR}/libsnark
  ${DEPENDS_DIR}/libsnark/depends/libff
  ${DEPENDS_DIR}/libsnark/depends/libfqfft)

add_library(mixer STATIC ../circuit/mixer.cpp)

add_executable(mixer_cli ../circuit/mixer_cli.cpp)
target_link_libraries(mixer_cli ethsnarks_common SHA3IUF)

add_executable(mixer_selftest ../circuit/mixer_selftest.cpp)
target_link_libraries(mixer_selftest ethsnarks_common SHA3IUF)

add_executable(mixer_js ../circuit/mixer.cpp)
target_link_libraries(mixer_js ethsnarks_common SHA3IUF)

# Bleh.. have to double-escape stuff and prefix with "SHELL:..." otherwise it combines multiple options into a single `-s` flag
target_link_options(mixer_js PUBLIC "SHELL:-s EXPORTED_FUNCTIONS=[\\\"_mixer_prove_json\\\",\\\"_mixer_genkeys\\\",\\\"_mixer_verify\\\",\\\"_mixer_tree_depth\\\"]")
target_link_options(mixer_js PUBLIC "SHELL:-s EXTRA_EXPORTED_RUNTIME_METHODS=[\\\"ccall\\\",\\\"cwrap\\\"]")

target_link_options(mixer_js PUBLIC "SHELL:-s FORCE_FILESYSTEM=1")
target_link_options(mixer_js PUBLIC "SHELL:-s DEFAULT_LIBRARY_FUNCS_TO_INCLUDE=[\\\"$Browser\\\"]")
