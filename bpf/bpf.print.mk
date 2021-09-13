# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

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

