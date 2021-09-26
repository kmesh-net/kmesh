# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

cmake_minimum_required(VERSION 3.12.1)
project(codehub.com/kmesh/bpf)

# debug
#set(CMAKE_VERBOSE_MAKEFILE ON)

# path
set(INCLUDE_PATH ${PROJECT_SOURCE_DIR}/include)

# compile
set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_FLAGS "-O2 -g -Wall -Werror -target bpf")

include_directories(${INCLUDE_PATH})

# OBJECT does not archive or link
add_library(bpf_sock.o OBJECT kmesh/bpf_sock.c)
add_library(bpf_sockops.o OBJECT sockmap/bpf_sockops.c)
add_library(bpf_redirect.o OBJECT sockmap/bpf_redirect.c)