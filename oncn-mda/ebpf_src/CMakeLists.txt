# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Kmesh

MESSAGE("======================Enter ebpf folder=======================")
set(CMAKE_C_COMPILER "clang")
set(CMAKE_C_FLAGS "-g -Wall -O2 -Werror -D_FORTIFY_SOURCE=2 -Wno-deprecated-declarations -ftrapv -target bpf -D__x86_64__ -fPIC")

set(LIBRARY_OUTPUT_PATH ${DEPLOY_LIB})

add_library(sock_ops OBJECT sock_ops.c)
add_library(sock_redirect OBJECT sock_redirect.c)

MESSAGE("======================Leave ebpf folder=======================")
