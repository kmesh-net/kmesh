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

