obj-m := kmesh.o
kmesh-objs = kmesh_main.o defer_connect.o \
	kmesh_parse_protocol_data.o \
	kmesh_parse_http_1_1.o

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

ccflags-y += -Wno-discarded-qualifiers

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD)

clean:
	@rm -rf *.o *.mod *.mod.c *.mod.o *.ko *.order *.symvers .*.cmd
