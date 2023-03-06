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

ROOT_DIR ?= $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

ifeq ($(V),1)
	QUIET =
	printlog =
else
	QUIET = @
	printlog = @printf '  %-8s %s%s\n'						\
				"$(1)"										\
				"$(patsubst $(ROOT_DIR)/%,%,$(2))"	\
				"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

find_source = $(shell find $(1) -name $(2))
