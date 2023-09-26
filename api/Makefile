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
# Create: 2022-02-09

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../mk/bpf.print.mk
include ../mk/bpf.vars.mk

C_OUTPUT_DIR := v2-c
GO_OUTPUT_DIR := v2
GO_BUILD_DIR := openmesh.io/mesh/api

PROTO_PATH := ../
PROTO_SRC := $(call find_source, ../api, *.proto)

.PHONY: all install clean

all:

	$(call printlog, PROTO, api/$(C_OUTPUT_DIR))
	$(QUIET) protoc-c --proto_path=$(PROTO_PATH) --c_out=.  $(PROTO_SRC)
	$(QUIET) mkdir -p $(C_OUTPUT_DIR)
	$(QUIET) cp -rf api/* $(C_OUTPUT_DIR); rm -rf api
	$(QUIET) find $(C_OUTPUT_DIR) -name *pb-c* | xargs sed -i 's/#include \"api\//#include \"/g'

	$(call printlog, PROTO, api/$(GO_OUTPUT_DIR))
	$(QUIET) protoc --proto_path=$(PROTO_PATH) --go_out=. $(PROTO_SRC)
	$(QUIET) mkdir -p $(GO_OUTPUT_DIR)
	$(QUIET) cp -rf $(GO_BUILD_DIR)/* $(GO_OUTPUT_DIR); rm -rf openmesh.io
	$(QUIET) find $(GO_OUTPUT_DIR) -name *pb.go | xargs sed -i 's/mesh\/api/mesh\/api\/v2/g'

install:

clean:
	$(call printlog, CLEAN, $(C_OUTPUT_DIR) $(GO_OUTPUT_DIR))
	$(QUIET) rm -rf $(C_OUTPUT_DIR) $(GO_OUTPUT_DIR)
