cmake_minimum_required(VERSION 3.16)
project(pqc_crypto_tool CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL REQUIRED)

find_path(OQS_INCLUDE_DIR oqs/oqs.h)
find_library(OQS_LIBRARY NAMES oqs liboqs)

if(NOT OQS_INCLUDE_DIR OR NOT OQS_LIBRARY)
    message(FATAL_ERROR
        "لم يتم العثور على مكتبة liboqs على النظام.\n"
        "ثبّتها أولاً (راجع README.md لتعليمات كاملة)، باختصار:\n"
        "  git clone --depth=1 https://github.com/open-quantum-safe/liboqs\n"
        "  cmake -S liboqs -B liboqs/build -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release\n"
        "  cmake --build liboqs/build --parallel\n"
        "  sudo cmake --install liboqs/build\n"
        "  sudo ldconfig")
endif()

add_library(pqc_crypto
    src/pqc_crypto.cpp
)
target_include_directories(pqc_crypto PUBLIC include ${OQS_INCLUDE_DIR})
target_link_libraries(pqc_crypto PUBLIC ${OQS_LIBRARY} OpenSSL::Crypto)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(pqc_crypto PRIVATE -O2)
endif()
target_compile_options(pqc_crypto PRIVATE -Wall -Wextra)

add_executable(pqc_tool src/main.cpp)
target_link_libraries(pqc_tool PRIVATE pqc_crypto)
target_compile_options(pqc_tool PRIVATE -Wall -Wextra)

install(TARGETS pqc_tool RUNTIME DESTINATION bin)