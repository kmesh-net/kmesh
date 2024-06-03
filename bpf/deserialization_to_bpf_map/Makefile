# SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
# Copyright Authors of Kmesh

ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

include ../../mk/bpf.vars.mk
include ../../mk/bpf.print.mk

INCLUDES =

# compiler flags
LDFLAGS := -lbpf -lboundscheck
CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_CDEFINE)
CFLAGS += -fstack-protector -fPIC
CFLAGS += -Wall -Werror

SOURCES = $(wildcard *.c)
OBJECTS = $(subst .c,.o,$(SOURCES))
# target
APPS := libkmesh_deserial.so

.PHONY: all install clean

all: $(APPS)

$(APPS): $(OBJECTS)
	$(call printlog, BUILD, bpf/deserialization_to_bpf_map/$@)
	$(QUIET) $(CLANG) $(CFLAGS) $(LDFLAGS) -shared $^ -o $@

%.o: %.c
	$(call printlog, BUILD, bpf/deserialization_to_bpf_map/$@)
	$(QUIET) $(CLANG) $(CFLAGS) $(INCLUDES) -c $^ -o $@

install:
	$(call printlog, INSTALL, $(INSTALL_LIB)/$(APPS))
	$(QUIET) install -Dp -m 0500 $(APPS) $(INSTALL_LIB)

uninstall:
	$(call printlog, UNINSTALL, $(INSTALL_LIB)/$(APPS))
	$(QUIET) rm -rf $(INSTALL_LIB)/$(APPS)

clean:
	$(call printlog, CLEAN, $(APPS))
	$(QUIET) rm -rf $(APPS) $(APPS) $(OBJECTS)

