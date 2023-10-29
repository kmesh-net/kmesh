# Copyright 2023 The Kmesh Authors.

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
APPS3 := mdacore

.PHONY: all install uninstall clean

all:
	$(QUIET) find $(ROOT_DIR)/mk -name "*.pc" | xargs sed -i "s#^prefix=.*#prefix=${ROOT_DIR}#g"

	$(QUIET) make -C api
	$(QUIET) make -C api/v2-c
	$(QUIET) make -C bpf/deserialization_to_bpf_map
	
	$(QUIET) $(GO) generate bpf/kmesh/bpf2go/bpf2go.go
	
	$(call printlog, BUILD, $(APPS1))
	$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
		$(GO) build -tags $(ISENHANCED_KERNEL) -o $(APPS1) $(GOFLAGS) ./daemon/main.go)
	
	$(call printlog, BUILD, $(APPS2))
	$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
		$(GO) build -o $(APPS2) $(GOFLAGS) ./cmd/main.go)
	
	$(call printlog, BUILD, "kernel")
	$(QUIET) make -C kernel/ko_src

	$(call printlog, BUILD, $(APPS3))
	$(QUIET) cd oncn-mda && cmake . -B build && make -C build

install:
	$(QUIET) make install -C api/v2-c
	$(QUIET) make install -C bpf/deserialization_to_bpf_map
	$(QUIET) make install -C kernel/ko_src

	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS1))
	$(QUIET) install -Dp -m 0500 $(APPS1) $(INSTALL_BIN)
	
	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS2))
	$(QUIET) install -Dp -m 0500 $(APPS2) $(INSTALL_BIN)

	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS3))
	$(QUIET) install -Dp -m 0500 oncn-mda/deploy/$(APPS3) $(INSTALL_BIN)
	$(QUIET) install -Dp -m 0400 oncn-mda/build/ebpf_src/CMakeFiles/sock_ops.dir/sock_ops.c.o /usr/share/oncn-mda/sock_ops.c.o
	$(QUIET) install -Dp -m 0400 oncn-mda/build/ebpf_src/CMakeFiles/sock_redirect.dir/sock_redirect.c.o /usr/share/oncn-mda/sock_redirect.c.o

uninstall:
	$(QUIET) make uninstall -C api/v2-c
	$(QUIET) make uninstall -C bpf/deserialization_to_bpf_map
	$(QUIET) make uninstall -C kernel/ko_src

	$(call printlog, UNINSTALL, $(INSTALL_BIN)/$(APPS1))
	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS1)
	$(call printlog, UNINSTALL, $(INSTALL_BIN)/$(APPS2))
	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS2)
	$(call printlog, UNINSTALL, $(INSTALL_BIN)/$(APPS3))
	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS3)

clean:
	$(call printlog, CLEAN, $(APPS1))
	$(QUIET) rm -rf $(APPS1) $(APPS1)

	$(call printlog, CLEAN, $(APPS2))
	$(QUIET) rm -rf $(APPS2) $(APPS2)

	$(call printlog, CLEAN, $(APPS3))
	$(QUIET) rm -rf oncn-mda/build
	$(QUIET) rm -rf oncn-mda/deploy

	$(QUIET) make clean -C api/v2-c
	$(QUIET) make clean -C bpf/deserialization_to_bpf_map
	$(call printlog, CLEAN, "kernel")
	$(QUIET) make clean -C kernel/ko_src
