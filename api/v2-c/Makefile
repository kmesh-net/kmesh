# Copyright (c) 2019 Huawei Technologies Co., Ltd.

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

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../../mk/bpf.vars.mk
include ../../mk/bpf.print.mk

INCLUDES = -I./

# compiler flags
LDFLAGS := -lprotobuf-c
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -fstack-protector -fPIC
CFLAGS += -Wall -Werror

SOURCES = $(wildcard */*.c)
OBJECTS = $(subst .c,.o,$(SOURCES))
# target
APPS := libkmesh_api_v2_c.so

.PHONY: all install clean

all: $(APPS)

$(APPS): $(OBJECTS)
	$(call printlog, BUILD, api/v2-c/$@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) -shared $^ -o $@

%.o: %.c
	$(call printlog, BUILD, api/v2-c/$@)
	$(QUIET) $(CLANG) $(CFLAGS) $(INCLUDES) -c $^ -o $@

install:
	$(call printlog, INSTALL, $(INSTALL_LIB)/$(APPS))
	$(QUIET) install -Dp -m 0550 $(APPS) $(INSTALL_LIB)

uninstall:
	$(call printlog, UNINSTALL, $(INSTALL_LIB)/$(APPS))
	$(QUIET) rm -rf $(INSTALL_LIB)/$(APPS)

clean:
	$(call printlog, CLEAN, $(APPS))
	$(QUIET) rm -rf $(APPS) $(APPS) $(OBJECTS)

