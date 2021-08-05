# Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
# Description: 

CURRENT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# tools
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# header file
VMLINUX := ../../vmlinux/vmlinux.h

INCLUDES := -I$(CURRENT_DIR)/include \
			-I$(OUTPUT)

# compiler flags
LDFLAGS = -lbpf
CFLAGS := -O2 -g -Wall

# target
APPS = sockops_ip4.bpf.o redirect_tcp.bpf.o
APPS += sockops_ip4.skel.h redirect_tcp.skel.h

OUTPUT := build
TARGETS = $(patsubst %,$(OUTPUT)/%,$(APPS))

# Get Clang's default includes on this system. We'll explicitly add these dirs
# to the includes list when compiling with `-target bpf` because otherwise some
# architecture-specific dirs will be "missing" on some architectures/distros -
# headers such as asm/types.h, asm/byteorder.h, asm/socket.h, asm/sockios.h,
# sys/cdefs.h etc. might be missing.
#
# Use '-idirafter': Don't interfere with include mechanics except where the
# build would have failed anyways.
CLANG_BPF_SYS_INCLUDES = $(shell $(CLANG) -v -E - </dev/null 2>&1 \
	| sed -n '/<...> search starts here:/,/End of search list./{ s| \(/.*\)|-idirafter \1|p }')

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n'						\
			"$(1)"										\
			"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))"	\
			"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all
all: $(TARGETS)


.PHONY: clean
clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APPS)

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Build BPF code
$(OUTPUT)/%.bpf.o: %.bpf.c | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) $(CFLAGS) $(LDFLAGS) $(INCLUDES) $(CLANG_BPF_SYS_INCLUDES) \
		-target bpf -c $(filter %.c,$^) -o $@
	$(Q)$(LLVM_STRIP) -g $@ #strip useless DWARF info

# Generate BPF skeletons
$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build user-space code
# todo


# delete failed targets
.DELETE_ON_ERROR:

# keep intermediate (.skel.h, .bpf.o, etc) targets
.SECONDARY:
