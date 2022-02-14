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

BUILD_DIR := v1
GO_BUILD_DIR := openeuler.io/mesh/api/$(BUILD_DIR)

PROTO_PATH := ../
PROTO_SRC := $(call find_source, ../api, *.proto)

.PHONY: all install clean

all:
	$(call printlog, BUILD, $(PROTO_SRC))
	$(QUIET) protoc-c --proto_path=$(PROTO_PATH) --c_out=.  $(PROTO_SRC)
	$(QUIET) mv api $(BUILD_DIR)
	$(QUIET) find $(BUILD_DIR) -name *pb-c* | xargs sed -i 's/#include \"api\//#include \"/g'

	$(QUIET) protoc --proto_path=$(PROTO_PATH) --go_out=. $(PROTO_SRC)
	$(QUIET) cp -rf $(GO_BUILD_DIR)/* $(BUILD_DIR)
	$(QUIET) rm -rf openeuler.io
install:

clean:
	$(call printlog, CLEAN, $(BUILD_DIR))
	$(QUIET) rm -rf $(BUILD_DIR)
