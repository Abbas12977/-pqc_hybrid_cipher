cmake_minimum_required(VERSION 3.16)
project(pqc_crypto_tool CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# متغّير حتى تدلي الـ CMake على مسار liboqs إذا جانت بمكان مخصص
set(OQS_ROOT_DIR "" CACHE PATH "مسار مجلد مكتبة liboqs")

# البحث عن مكتبة OpenSSL
find_package(OpenSSL REQUIRED)

# البحث عن ملف الترويسة مع تدلية النظام على المسارات المحتملة
find_path(OQS_INCLUDE_DIR
    NAMES oqs/oqs.h
    HINTS
        ${OQS_ROOT_DIR}/include
        ${CMAKE_SOURCE_DIR}/libs/liboqs/include
        ${CMAKE_SOURCE_DIR}/third_party/liboqs/include
)

# البحث عن ملف المكتبة المبنّية (lib/lib64)
find_library(OQS_LIBRARY
    NAMES oqs liboqs
    HINTS
        ${OQS_ROOT_DIR}/lib
        ${OQS_ROOT_DIR}/lib64
        ${CMAKE_SOURCE_DIR}/libs/liboqs/lib
        ${CMAKE_SOURCE_DIR}/third_party/liboqs/lib
)

if(NOT OQS_INCLUDE_DIR OR NOT OQS_LIBRARY)
    message(FATAL_ERROR
        "جا وين المكتبة؟ ما لقينا liboqs!\n"
        "ثبتها بالنظام، أو انطي المسار المباشر وانت تبني بـ CMake مثل هيج:\n"
        "  cmake -B build -DOQS_ROOT_DIR=/مسار/مكتبتك/liboqs\n"
        "أو انسخ ملفات المكتبة وحطها داخل مجلد libs/liboqs بمشروعك.")
endif()

add_library(pqc_crypto
    src/pqc_crypto.cpp
)

target_include_directories(pqc_crypto PUBLIC 
    include 
    ${OQS_INCLUDE_DIR}
)

target_link_libraries(pqc_crypto PUBLIC 
    ${OQS_LIBRARY} 
    OpenSSL::Crypto
)

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(pqc_crypto PRIVATE -O2)
endif()
target_compile_options(pqc_crypto PRIVATE -Wall -Wextra)

add_executable(pqc_tool src/main.cpp)
target_link_libraries(pqc_tool PRIVATE pqc_crypto)
target_compile_options(pqc_tool PRIVATE -Wall -Wextra)

install(TARGETS pqc_tool RUNTIME DESTINATION bin)
