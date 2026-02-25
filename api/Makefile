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
# Create: 2022-02-09

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../mk/bpf.print.mk
include ../mk/bpf.vars.mk

C_OUTPUT_DIR := v2-c
PROTO_PATH := ../
PROTO_SRC := $(call find_source, ../api, *.proto)
WORKLOAD_PROTO_SRC := workloadapi/workload.proto

.PHONY: gen-proto gen-workload-proto install clean

gen-proto:

	$(QUIET) bash ../hack/install-proto.sh
	$(call printlog, PROTO, api/$(C_OUTPUT_DIR))
	$(QUIET) bash ../hack/gen-protoc.sh $(PROTO_PATH) $(PROTO_SRC)
	$(QUIET) mkdir -p $(C_OUTPUT_DIR)
	$(QUIET) cp -rf api/* $(C_OUTPUT_DIR); rm -rf api
	$(QUIET) find $(C_OUTPUT_DIR) -name *pb-c* | xargs sed -i 's/#include \"api\//#include \"/g'
	$(call printlog, PROTO, workloadapi)
	$(QUIET) protoc --proto_path=. --go_out=workloadapi --go_opt=paths=source_relative $(WORKLOAD_PROTO_SRC)

install:

clean:
	$(call printlog, CLEAN, $(C_OUTPUT_DIR))
	$(QUIET) rm -rf $(C_OUTPUT_DIR)
	$(QUIET) rm -f workloadapi/*.pb.go
