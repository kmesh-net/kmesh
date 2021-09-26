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

INSTALL_BIN ?= $(DESTDIR)/$(BINDIR)/kmesh
