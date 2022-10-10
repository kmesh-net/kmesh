# Copyright (c) 2019 Huawei Technologies Co., Ltd.
# MeshAccelerating is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#	 http://license.coscl.org.cn/MulanPSL2
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
# PURPOSE.
# See the Mulan PSL v2 for more details.
# Author: nlgwcy
# Create: 2022-02-17

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../../mk/bpf.vars.mk
include ../../mk/bpf.print.mk

PROTOBUF_H := $(ROOT_DIR)/../../api/v2-c

INCLUDES := -I$(ROOT_DIR)/include
INCLUDES += -I$(ROOT_DIR)/../include
INCLUDES += $(CLANG_BPF_SYS_INCLUDES)
INCLUDES += -I$(PROTOBUF_H)
INCLUDES += -I/usr/include/

# compiler flags
#LDFLAGS = -lbpf
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -target bpf

# target
APPS := $(patsubst %.c, %.o, $(wildcard *.c))

.PHONY: all install clean

all: $(APPS)

%.o: %.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) $(INCLUDES) \
		-c $(filter %.c,$^) -o $@
	$(QUIET) $(LLVM_STRIP) -g $@ #strip useless DWARF info

install:
	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS))
	$(QUIET) install -dp -m 0750 $(INSTALL_BIN)
	$(QUIET) install -Dp -m 0500 $(ROOT_DIR)/$(APPS) $(INSTALL_BIN)

clean:
	$(call printlog, CLEAN, $(APPS))
	$(QUIET) rm -rf $(APPS)
	$(QUIET) rm -rf $(INSTALL_BIN)
