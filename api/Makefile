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
# Create: 2022-02-09

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../mk/bpf.print.mk
include ../mk/bpf.vars.mk

C_OUTPUT_DIR := v2-c
GO_OUTPUT_DIR := v2
GO_BUILD_DIR := openeuler.io/mesh/api

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
	$(QUIET) cp -rf $(GO_BUILD_DIR)/* $(GO_OUTPUT_DIR); rm -rf openeuler.io
	$(QUIET) find $(GO_OUTPUT_DIR) -name *pb.go | xargs sed -i 's/mesh\/api/mesh\/api\/v2/g'

install:

clean:
	$(call printlog, CLEAN, $(C_OUTPUT_DIR) $(GO_OUTPUT_DIR))
	$(QUIET) rm -rf $(C_OUTPUT_DIR) $(GO_OUTPUT_DIR)
