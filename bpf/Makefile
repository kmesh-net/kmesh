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

include ./bpf.print.mk

.PHONY: all install clean

all:
	$(QUIET) make -C kmesh
	$(QUIET) make -C sockmap

install:
	$(QUIET) make install -C kmesh
	$(QUIET) make install -C sockmap

clean:
	$(QUIET) make clean -C kmesh
	$(QUIET) make clean -C sockmap
