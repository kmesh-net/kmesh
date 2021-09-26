# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ./bpf.print.mk

.PHONY: all install clean

all:
	$(QUIET) make -C kmesh
	$(QUIET) make -C sockmap

install:
	$(QUIET) make install -C kmesh
	$(QUIET) make install -C sockmap

clean:
	$(QUIET) make clean -C kmesh
	$(QUIET) make clean -C sockmap
