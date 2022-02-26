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

include ../../mk/bpf.vars.mk
include ../../mk/bpf.print.mk

INCLUDES =

# compiler flags
#LDFLAGS := -lbpf
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -fstack-protector -fPIC
CFLAGS += -Werror -Wall

SOURCES = $(wildcard *.c)
OBJECTS = $(subst .c,.o,$(SOURCES))
# target
APPS := libdeserial.so

.PHONY: all install clean

all: $(APPS)

$(APPS): $(OBJECTS)
	$(call printlog, BUILD, $@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) -shared $^ -o $@

$(OBJECTS): $(SOURCES)
	$(call printlog, BUILD, $@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) $(INCLUDES) -c $^ -o $@

install:

clean:
	$(call printlog, CLEAN, $(APPS) $(OBJECTS))
	$(QUIET) rm -rf $(APPS) $(OBJECTS)

