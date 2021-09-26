# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../bpf.vars.mk
include ../bpf.print.mk

INCLUDES := -I$(ROOT_DIR)/../include
INCLUDES += $(CLANG_BPF_SYS_INCLUDES)

# compiler flags
#LDFLAGS = -lbpf
CFLAGS := -O2 -g -Wall

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
		-target bpf -c $(filter %.c,$^) -o $@
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
