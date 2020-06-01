cmake_minimum_required(VERSION 3.16)

project(inftool)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SRC_FILES src/inftool.cpp)

add_executable(inftool ${SRC_FILES})

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(inftool PRIVATE -Wall -Wextra -Wno-address-of-packed-member -Wconversion)
endif()

install(TARGETS inftool DESTINATION bin)
