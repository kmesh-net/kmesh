ROOT_DIR := $(shell git rev-parse --show-toplevel)

.PHONY: all build-bpf-tests run clean

all: build-bpf-tests

build-bpf-tests:
	@echo "Building BPF unit tests..."
	@bash $(ROOT_DIR)/test/bpf_ut/build_bpf_ut_tests.sh

run: build-bpf-tests
	@echo "Running BPF unit tests..."
	@cd $(ROOT_DIR)/test/bpf_ut/bpftest && go test -v ./...

clean:
	@echo "Cleaning build files..."
	@rm -f $(ROOT_DIR)/test/bpf_ut/*.o
	@rm -f $(ROOT_DIR)/test/bpf_ut/*.d
