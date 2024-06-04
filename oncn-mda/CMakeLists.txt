# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Kmesh

cmake_minimum_required(VERSION 3.12.1)
project(macli LANGUAGES C)
set(CMAKE_VERBOSE_MAKEFILE ON)

include_directories("${PROJECT_SOURCE_DIR}/include")

set(DEPLOY_PROGRAM "${PROJECT_SOURCE_DIR}/deploy")

add_subdirectory(ebpf_src)
add_subdirectory(cli_src)
