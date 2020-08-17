# CMakeLists.txt - cmake build for goosig
# Copyright (c) 2020, Christopher Jeffrey (MIT License).
# https://github.com/handshake-org/goosig

cmake_minimum_required(VERSION 3.4)
project(goosig LANGUAGES C)

include(CheckLibraryExists)
include(TestBigEndian)

set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 99)

option(GOO_ENABLE_GMP "Use gmp if available" ON)

set(goo_sources src/goo/drbg.c
                src/goo/goo.c
                src/goo/hmac.c
                src/goo/sha256.c)

set(goo_defines)
set(goo_cflags)
set(goo_libs)

if(MSVC)
  list(APPEND goo_cflags /wd4146
                         /wd4244
                         /wd4267
                         /wd4334)
else()
  list(APPEND goo_cflags -pedantic
                         -Wall
                         -Wextra
                         -Wcast-align
                         -Wno-long-long
                         -Wshadow)
endif()

check_library_exists(gmp __gmpz_jacobi "" GOO_HAS_GMP)

if(GOO_ENABLE_GMP AND GOO_HAS_GMP)
  list(APPEND goo_defines GOO_HAS_GMP)
  list(APPEND goo_libs gmp)
else()
  list(APPEND goo_sources src/goo/mini-gmp.c)
  if(NOT MSVC)
    list(APPEND goo_cflags -Wno-unused-parameter
                           -Wno-unused-variable
                           -Wno-sign-compare)
  endif()
endif()

test_big_endian(GOO_BIGENDIAN)

if(GOO_BIGENDIAN)
  list(APPEND goo_defines WORDS_BIGENDIAN)
endif()

add_node_library(goo STATIC ${goo_sources})
target_compile_definitions(goo PRIVATE ${goo_defines})
target_compile_options(goo PRIVATE ${goo_cflags})
target_link_libraries(goo INTERFACE ${goo_libs})
set_property(TARGET goo PROPERTY C_VISIBILITY_PRESET default)
set_property(TARGET goo PROPERTY C_STANDARD_REQUIRED ON)
set_property(TARGET goo PROPERTY C_EXTENSIONS OFF)
set_property(TARGET goo PROPERTY C_STANDARD 90)

set(goosig_cflags)

if(MSVC)
  list(APPEND goosig_cflags /wd4146
                            /wd4244
                            /wd4267
                            /wd4334)
else()
  list(APPEND goosig_cflags -Wall
                            -Wextra)
endif()

add_node_module(goosig src/goosig.c)
target_compile_options(goosig PRIVATE ${goosig_cflags})
target_link_libraries(goosig PRIVATE goo)
