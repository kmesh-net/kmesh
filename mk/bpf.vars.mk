# Copyright 2023 The Kmesh Authors.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
