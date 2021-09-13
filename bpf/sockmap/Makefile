# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../bpf.vars.mk
include ../bpf.echo.mk

INCLUDES := -I$(ROOT_DIR)/../include
INCLUDES += $(CLANG_BPF_SYS_INCLUDES)

# compiler flags
#LDFLAGS = -lbpf
CFLAGS := -O2 -g -Wall

# target
APPS := bpf_sock.o

# target
APPS = sockops_ip4.bpf.o redirect_tcp.bpf.o
APPS += sockops_ip4.skel.h redirect_tcp.skel.h

.PHONY: all clean install test

all: $(APPS)

# Build BPF code
%.bpf.o: %.bpf.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) $(INCLUDES) \
		-target bpf -c $(filter %.c,$^) -o $@
	$(QUIET) $(LLVM_STRIP) -g $@ #strip useless DWARF info

# Generate BPF skeletons
%.skel.h: %.bpf.o
	$(call printlog, GEN-SKEL, $@)
	$(QUIET) $(BPFTOOL) gen skeleton $< > $@

clean:
	$(call printlog, CLEAN, $(APPS))
	$(QUIET) rm -rf $(APPS)

install:

test: