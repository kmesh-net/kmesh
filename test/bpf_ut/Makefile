MAKEFLAGS += -r

QUIET ?= @
CLANG ?= clang
GO ?= go

ROOT_DIR := $(shell git rev-parse --show-toplevel)
TEST_DIR := $(ROOT_DIR)/test/bpf_ut

FLAGS := -isystem /usr/include -I/usr/local/include
FLAGS += -I./include  -I$(ROOT_DIR)/bpf/include  
FLAGS += -fPIC -D__NR_CPUS__=$(shell nproc --all) -D__TARGET_ARCH_x86_64 -D__x86_64__ -D_GNU_SOURCE -DKERNEL_VERSION_HIGHER_5_13_0=1
FLAGS += -O2 -g

CLANG_FLAGS := ${FLAGS} --target=bpf -std=gnu99
# eBPF verifier enforces unaligned access checks where necessary, so don't
# let clang complain too early.
CLANG_FLAGS += -Wall -Wextra
CLANG_FLAGS += -Wno-address-of-packed-member
CLANG_FLAGS += -Wno-unknown-warning-option
CLANG_FLAGS += -Wno-gnu-variable-sized-type-not-at-end
CLANG_FLAGS += -Wenum-conversion
CLANG_FLAGS += -Wimplicit-fallthrough
# Create dependency files for each .o file.
CLANG_FLAGS += -MD

.PHONY: all clean run

all: xdp_shutdown_in_userspace_test.o \
		xdp_authz_offload_test.o          \
		workload_sockops_test.o           \
		tc_mark_encrypt_test.o            \
		tc_mark_decrypt_test.o


XDP_FLAGS = -I$(ROOT_DIR)/bpf/kmesh/ -I$(ROOT_DIR)/bpf/kmesh/workload/include -I$(ROOT_DIR)/api/v2-c
xdp_%.o: xdp_%.c
	$(QUIET) $(CLANG) $(CLANG_FLAGS) $(XDP_FLAGS) -c $< -o $@

WORKLOAD_SOCKOPS_FLAGS = -I$(ROOT_DIR)/bpf/kmesh/ -I$(ROOT_DIR)/bpf/kmesh/probes -I$(ROOT_DIR)/bpf/kmesh/workload/include -I$(ROOT_DIR)/api/v2-c
workload_sockops_test.o: workload_sockops_test.c
	$(QUIET) $(CLANG) $(CLANG_FLAGS) $(WORKLOAD_SOCKOPS_FLAGS) -c $< -o $@

TC_FLAGS = -I$(ROOT_DIR)/bpf/kmesh/ -I$(ROOT_DIR)/bpf/kmesh/general/include -I$(ROOT_DIR)/bpf/kmesh/general -I$(ROOT_DIR)/api/v2-c
tc_mark_encrypt_test.o: tc_mark_encrypt_test.c
	$(QUIET) $(CLANG) $(CLANG_FLAGS) $(TC_FLAGS) -c $< -o $@
tc_mark_decrypt_test.o: tc_mark_decrypt_test.c
	$(QUIET) $(CLANG) $(CLANG_FLAGS) $(TC_FLAGS) -c $< -o $@

clean:
	$(QUIET) rm -f $(wildcard *.o)
	$(QUIET) rm -f $(wildcard *.d)
	$(QUIET) echo "clean all object files"

BPF_TEST_FLAGS:=
ifneq ($(shell id -u), 0)
		BPF_TEST_FLAGS += -exec "sudo -E"
endif
ifeq ($(V),1)
    BPF_TEST_FLAGS += -test.v
endif
ifeq ($(COVER),1)
	ifndef COVERFORMAT
		COVERFORMAT:=html
	endif
    BPF_TEST_FLAGS += -coverage-report $(ROOT_DIR)/bpf-coverage.$(COVERFORMAT) -coverage-format $(COVERFORMAT)
ifdef NOCOVER
    BPF_TEST_FLAGS += -no-test-coverage "$(NOCOVER)"
endif
endif
ifeq ($(INSTRLOG),1)
    BPF_TEST_FLAGS += -instrumentation-log $(ROOT_DIR)/test/bpf-instrumentation.log
endif
ifdef RUN
    BPF_TEST_FLAGS += -run $(RUN)
endif
ifdef BPF_TEST_DUMP_CTX
    BPF_TEST_FLAGS += -dump-ctx
endif
ifdef BPF_TEST_FILE
	BPF_TEST_FLAGS += -test $(BPF_TEST_FILE)
endif

run: all
	$(GO) test ./bpftest -bpf-ut-path $(ROOT_DIR)/test/bpf_ut $(BPF_TEST_FLAGS)

-include $(TEST_OBJECTS:.o=.d)
