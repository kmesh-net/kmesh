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

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../bpf.vars.mk
include ../bpf.print.mk

INCLUDES := -I$(ROOT_DIR)/../include
INCLUDES += $(CLANG_BPF_SYS_INCLUDES)

# compiler flags
#LDFLAGS = -lbpf
CFLAGS := -O2 -g -Wall -target bpf

# target
APPS := bpf_sock.o

# target
APPS = bpf_sockops.o bpf_redirect.o
APPS += bpf_sockops.skel.h bpf_redirect.skel.h

.PHONY: all clean install

all: $(APPS)

# Build BPF code
%.o: %.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) $(INCLUDES) \
		-c $(filter %.c,$^) -o $@
	$(QUIET) $(LLVM_STRIP) -g $@ #strip useless DWARF info

# Generate BPF skeletons
%.skel.h: %.o
	$(call printlog, GEN-SKEL, $@)
	$(QUIET) $(BPFTOOL) gen skeleton $< > $@

clean:
	$(call printlog, CLEAN, $(APPS))
	$(QUIET) rm -rf $(APPS)
	$(QUIET) rm -rf $(INSTALL_BIN)

install:
	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS))
	$(QUIET) install -dp -m 0750 $(INSTALL_BIN)
	$(QUIET) install -Dp -m 0500 $(ROOT_DIR)/$(APPS) $(INSTALL_BIN)
