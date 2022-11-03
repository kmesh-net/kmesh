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
	install -dp -m 0550 /lib/modules/kmesh
	install -Dp -m 0440 kmesh.ko /lib/modules/kmesh
	ln -s /lib/modules/kmesh/kmesh.ko /lib/modules/`uname -r` > /dev/null
	depmod -a

uninstall:
	rm -rf /lib/modules/`uname -r`/kmesh.ko
	rm -rf /lib/modules/kmesh
	depmod -a

clean:
	@rm -rf *.o *.mod *.mod.c *.mod.o *.ko *.order *.symvers .*.cmd