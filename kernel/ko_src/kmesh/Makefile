# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 as
# published by the Free Software Foundation
#
# Author: liuxin
# Create: 2022-08-24

obj-m := kmesh.o
kmesh-objs = kmesh_main.o defer_connect.o \
	kmesh_parse_protocol_data.o \
	kmesh_parse_http_1_1.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ccflags-y += -Wno-discarded-qualifiers

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

install:
	install -dp -m 0500 /lib/modules/kmesh
	install -Dp -m 0400 kmesh.ko /lib/modules/kmesh
	ln -sf /lib/modules/kmesh/kmesh.ko /lib/modules/`uname -r`
	depmod -a

uninstall:
	rm -rf /lib/modules/`uname -r`/kmesh.ko
	rm -rf /lib/modules/kmesh
	depmod -a

clean:
	@rm -rf *.o *.mod *.mod.c *.mod.o *.ko *.order *.symvers .*.cmd
