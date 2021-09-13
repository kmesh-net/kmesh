# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

ROOT_DIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# tools
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool
GO ?= go

# path
BINDIR ?= /usr/bin
LIBDIR ?= /usr/lib64
RUNDIR ?= /var/run
CONFDIR ?= /etc

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')