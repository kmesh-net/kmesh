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
# Create: 2021-12-08

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ./mk/bpf.vars.mk
include ./mk/bpf.print.mk

# compiler flags
GOFLAGS := $(EXTRA_GOFLAGS)

# target
APPS1 := kmesh-daemon
APPS2 := kmesh-cmd

.PHONY: all install uninstall clean

all:
	$(QUIET) cp depends/include/6.1/bpf_helper_defs_ext.h bpf/include/
	$(QUIET) find $(ROOT_DIR)/mk -name "*.pc" | xargs sed -i "s#^prefix=.*#prefix=${ROOT_DIR}#g"

	$(QUIET) make -C api
	$(QUIET) make -C api/v2-c
	$(QUIET) make -C bpf/deserialization_to_bpf_map
	
	$(QUIET) $(GO) generate bpf/kmesh/bpf2go/bpf2go.go
	
	$(call printlog, BUILD, $(APPS1))
	$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
		$(GO) build -o $(APPS1) $(GOFLAGS) ./daemon/main.go)
	
	$(call printlog, BUILD, $(APPS2))
	$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
		$(GO) build -o $(APPS2) $(GOFLAGS) ./cmd/main.go)
	
	$(call printlog, BUILD, "kernel")
	$(QUIET) make -C kernel/ko_src

install:
	$(QUIET) make install -C api/v2-c
	$(QUIET) make install -C bpf/deserialization_to_bpf_map
	$(QUIET) make install -C kernel/ko_src

	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS1))
	#$(QUIET) install -dp -m 0700 $(INSTALL_BIN)
	$(QUIET) install -Dp -m 0500 $(APPS1) $(INSTALL_BIN)
	
	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS2))
	$(QUIET) install -Dp -m 0500 $(APPS2) $(INSTALL_BIN)

uninstall:
	$(QUIET) make uninstall -C api/v2-c
	$(QUIET) make uninstall -C bpf/deserialization_to_bpf_map
	$(QUIET) make uninstall -C kernel/ko_src

	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS1)
	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS2)

clean:
	$(call printlog, CLEAN, $(APPS1))
	$(QUIET) rm -rf $(APPS1) $(APPS1)
	
	$(call printlog, CLEAN, $(APPS2))
	$(QUIET) rm -rf $(APPS2) $(APPS2)
	
	$(QUIET) make clean -C api/v2-c
	$(QUIET) make clean -C bpf/deserialization_to_bpf_map
	$(call printlog, CLEAN, "kernel")
	$(QUIET) make clean -C kernel/ko_src
