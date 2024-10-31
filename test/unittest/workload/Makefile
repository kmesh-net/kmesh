CFLAGS += -g3 -Wall -fPIC -I. -D__TARGET_ARCH_x86_64 -D__x86_64__ -D_GNU_SOURCE
CFLAGS += -isystem /usr/include
LIBS = bpf

WORKLOAD_DIR = ../../../bpf/kmesh/workload
TEST_DIR = .
INCLUDE_DIR = $(WORKLOAD_DIR)/../../include

FLAGS += -I$(WORKLOAD_DIR) -I../../../bpf/kmesh/workload/include/ctx -I../../../bpf/kmesh/workload/include/ -I../../../bpf/probes/ -I$(INCLUDE_DIR)

all: xdp_test

xdp_test: $(TEST_DIR)/xdp.bpf.o $(TEST_DIR)/xdp_test.skel.h
	gcc $(CFLAGS) $(FLAGS) -include /usr/include/errno.h -o $(TEST_DIR)/xdp_test $(TEST_DIR)/xdp_test.c -l$(LIBS)

$(TEST_DIR)/xdp.bpf.o: $(WORKLOAD_DIR)/xdp.c
	clang -target bpf $(CFLAGS) $(FLAGS) -O2 -g -c $< -o $@

$(TEST_DIR)/xdp_test.skel.h: $(TEST_DIR)/xdp.bpf.o
	bpftool gen skeleton $< > $@

.PHONY: clean
clean:
	rm -rf $(TEST_DIR)/xdp.bpf.o
	rm -rf $(TEST_DIR)/xdp_test.skel.h 
	rm -rf $(TEST_DIR)/xdp_test
	rm -rf preprocessed_output.c