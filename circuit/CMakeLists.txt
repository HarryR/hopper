cmake_minimum_required(VERSION 3.8)
project(argent-mixer C CXX)

if (IOS_BUILD)
    set(CMAKE_INSTALL_PREFIX  ../ios/Hopper/depends)
    set(PKG_CONFIG_EXECUTABLE /usr/local/bin/pkg-config)
    set(OPENSSL_INCLUDE_DIR /usr/local/include)
    set(OPENSSL_CRYPTO_LIBRARY /usr/local/opt/openssl/lib/libcrypto.dylib)
    set(GMP_INCLUDE_DIR /usr/local/include)
    set(GMPXX_INCLUDE_DIR /usr/local/include)
    set(GMP_LIBRARY ${CMAKE_INSTALL_PREFIX}/lib/libgmp.a)
    set(GMPXX_LIBRARY ${CMAKE_INSTALL_PREFIX}/lib/libgmpxx.a)
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON) #...is required...

add_subdirectory(../ethsnarks ../.build/ethsnarks EXCLUDE_FROM_ALL)
add_subdirectory(gadgets)

include_directories(
    ../ethsnarks/src
    ../circuit/gadgets/SHA3IUF
    ${DEPENDS_DIR}/json
    ${DEPENDS_DIR}/libsnark
    ${DEPENDS_DIR}/libsnark/depends/libff
    ${DEPENDS_DIR}/libsnark/depends/libfqfft)

add_library(mixer STATIC mixer.cpp)
target_link_libraries(mixer gmp ethsnarks_common SHA3IUF)
set_property(TARGET mixer PROPERTY POSITION_INDEPENDENT_CODE ON)

if (IOS_BUILD)
    install (TARGETS mixer ethsnarks_common SHA3IUF ff DESTINATION lib)
    install (FILES mixer.hpp DESTINATION include)
    install (FILES ../.keys/mixer.pk.raw DESTINATION data)
    install (FILES ../.keys/mixer.vk.json DESTINATION data)
else()
    add_library(mixer_shared SHARED mixer.cpp)
    target_link_libraries(mixer_shared gmp ethsnarks_common SHA3IUF)
    add_executable(mixer_cli mixer_cli.cpp)
    target_link_libraries(mixer_cli ethsnarks_common SHA3IUF)
endif()

