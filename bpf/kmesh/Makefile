# Copyright (c) 2019 Huawei Technologies Co., Ltd.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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

.PHONY: all clean

all: $(APPS)

%.o: %.c
	$(call printlog, BUILD, $@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) $(INCLUDES) \
		-c $(filter %.c,$^) -o $@
	$(QUIET) $(LLVM_STRIP) -g $@ #strip useless DWARF info

clean:
	$(call printlog, CLEAN, $(APPS))
	$(QUIET) rm -rf $(APPS)
