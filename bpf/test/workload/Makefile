CFLAGS += -g3 -Wall -fPIC -I. -D__TARGET_ARCH_x86_64 -D__x86_64__ -D_GNU_SOURCE
CFLAGS += -isystem /usr/include
LIBS = bpf

WORKLOAD_DIR = ../../kmesh/workload
TEST_DIR = .
INCLUDE_DIR = $(WORKLOAD_DIR)/../../include

FLAGS += -I$(WORKLOAD_DIR) -I../../kmesh/workload/include/ctx -I../../kmesh/workload/include/ -I../../kmesh/probes/ -I$(INCLUDE_DIR)

all: $(TEST_DIR)/cgroup_sock.bpf.o $(TEST_DIR)/cgroup_sock_test.skel.h $(TEST_DIR)/test

$(TEST_DIR)/cgroup_sock.bpf.o: $(WORKLOAD_DIR)/cgroup_sock.c
	clang -target bpf $(CFLAGS) $(FLAGS) -O2 -g -c $< -o $@

$(TEST_DIR)/cgroup_sock_test.skel.h: $(TEST_DIR)/cgroup_sock.bpf.o
	bpftool gen skeleton $< > $@

$(TEST_DIR)/test: $(TEST_DIR)/cgroup_sock_test.c $(TEST_DIR)/cgroup_sock_test.skel.h
	# @echo "Preprocessing..."
	# @gcc -E $(CFLAGS) $(FLAGS) $< > preprocessed_output.c
	# @echo "Grep for errno and ENOMEM..."
	# @grep -n -E 'errno|ENOMEM' preprocessed_output.c
	gcc $(CFLAGS) $(FLAGS) -include /usr/include/errno.h -o $@ $< -l$(LIBS)

.PHONY: clean
clean:
	rm -rf $(TEST_DIR)/cgroup_sock.bpf.o
	rm -rf $(TEST_DIR)/cgroup_sock_test.skel.h
	rm -rf $(TEST_DIR)/test
	rm -rf preprocessed_output.c