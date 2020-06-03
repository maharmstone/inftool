cmake_minimum_required(VERSION 3.16)

project(inftool)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_FILES src/inftool.cpp
	src/sign.cpp
	src/sha1.cpp)

add_executable(inftool ${SRC_FILES})

find_package(OpenSSL REQUIRED)

target_link_libraries(inftool ${OPENSSL_LIBRARIES})

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(inftool PRIVATE -Wall -Wextra -Wno-address-of-packed-member -Wconversion)
endif()

install(TARGETS inftool DESTINATION bin)
