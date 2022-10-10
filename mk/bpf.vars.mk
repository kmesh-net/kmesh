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

INSTALL_BIN ?= $(DESTDIR)/$(BINDIR)
INSTALL_LIB ?= $(DESTDIR)/$(LIBDIR)

EXTRA_GOFLAGS ?= -a
EXTRA_CFLAGS ?= -O2 -Wall
EXTRA_CDEFINE ?= -D__x86_64__
