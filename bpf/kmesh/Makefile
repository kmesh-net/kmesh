# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../bpf.vars.mk
include ../bpf.print.mk

INCLUDES := -I$(ROOT_DIR)/../include
INCLUDES += $(CLANG_BPF_SYS_INCLUDES)

# compiler flags
#LDFLAGS = -lbpf
CFLAGS := -O2 -g -Wall -target bpf

# target
APPS := cgroup_sock.o filter.o cluster.o

.PHONY: all install clean

all: $(APPS)

%.o: %.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) $(INCLUDES) \
		-c $(filter %.c,$^) -o $@
	$(QUIET) $(LLVM_STRIP) -g $@ #strip useless DWARF info

clean:
	$(call printlog, CLEAN, $(APPS))
	$(QUIET) rm -rf $(APPS)
	$(QUIET) rm -rf $(INSTALL_BIN)

install:
	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS))
	$(QUIET) install -dp -m 0750 $(INSTALL_BIN)
	$(QUIET) install -Dp -m 0500 $(ROOT_DIR)/$(APPS) $(INSTALL_BIN)
