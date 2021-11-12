# Copyright (c) 2019 Huawei Technologies Co., Ltd.
# MeshAccelerating is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#     http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# Author: LemmyHuang
# Create: 2021-09-17

cmake_minimum_required(VERSION 3.12.1)
project(openeuler.io/kmesh/bpf)

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