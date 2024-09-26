# Copyright 2023 The Kmesh Authors.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

VERSION ?= 0.5.0-rc.0
GIT_COMMIT_HASH ?= $(shell git rev-parse HEAD)
GIT_TREESTATE=$(shell if [ -n "$(git status --porcelain)" ]; then echo "dirty"; else echo "clean"; fi)
BUILD_DATE = $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
ROOT_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
	GOBIN=$(shell go env GOPATH)/bin
else
	GOBIN=$(shell go env GOBIN)
endif
export PATH := $(GOBIN):$(PATH)

include ./mk/bpf.vars.mk
include ./mk/bpf.print.mk

# compiler flags
CC=clang
CXX=clang++
GOFLAGS := $(EXTRA_GOFLAGS)
EXTLDFLAGS := '-fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack'
LDFLAGS := "-X google.golang.org/protobuf/reflect/protoregistry.conflictPolicy=warn \
			-X kmesh.net/kmesh/pkg/version.gitVersion=$(VERSION) \
			-X kmesh.net/kmesh/pkg/version.gitCommit=$(GIT_COMMIT_HASH) \
			-X kmesh.net/kmesh/pkg/version.gitTreeState=$(GIT_TREESTATE) \
			-X kmesh.net/kmesh/pkg/version.buildDate=$(BUILD_DATE) \
			-linkmode=external -extldflags $(EXTLDFLAGS)"

# target
APPS1 := kmesh-daemon
APPS2 := mdacore
APPS3 := kmesh-cni
APPS4 := kmeshctl

APPS := kmesh-daemon mdacore kmesh-cni kmeshctl

ifeq ($(BINARIES),)
    BINARIES := $(APPS)
endif


# If the hub is not explicitly set, use default to kmesh-net.
HUB ?= ghcr.io/kmesh-net
ifeq ($(HUB),)
  $(error "HUB cannot be empty")
endif

TARGET ?= kmesh
ifeq ($(TARGET),)
  $(error "TARGET cannot be empty")
endif

# If tag not explicitly set, default to the git sha.
TAG ?= $(shell git rev-parse --verify HEAD)
ifeq ($(TAG),)
  $(error "TAG cannot be empty")
endif

TMP_FILES := bpf/kmesh/bpf2go/bpf2go.go \
	config/kmesh_marcos_def.h \
	mk/api-v2-c.pc \
	mk/bpf.pc \
	bpf/kmesh/ads/include/config.h \
	bpf/include/bpf_helper_defs_ext.h \
	depends/include/bpf_helper_defs_ext.h

.PHONY: all
all:
	$(QUIET) find $(ROOT_DIR)/mk -name "*.pc" | xargs sed -i "s#^prefix=.*#prefix=${ROOT_DIR}#g"

	$(QUIET) make -C api/v2-c
	$(QUIET) make -C bpf/deserialization_to_bpf_map

	$(QUIET) $(GO) generate bpf/kmesh/bpf2go/bpf2go.go

	$(call printlog, BUILD, $(APPS1))
	$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
		$(GO) build -ldflags $(LDFLAGS) -tags $(ENHANCED_KERNEL) -o $(APPS1) $(GOFLAGS) ./daemon/main.go)

	$(call printlog, BUILD, "kernel")
	$(QUIET) make -C kernel/ko_src

	$(call printlog, BUILD, $(APPS2))
	$(QUIET) cd oncn-mda && cmake . -B build && make -C build

	$(call printlog, BUILD, $(APPS3))
	$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
		$(GO) build -ldflags $(LDFLAGS) -tags $(ENHANCED_KERNEL) -o $(APPS3) $(GOFLAGS) ./cniplugin/main.go)

	$(call printlog, BUILD, $(APPS4))
	$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
		$(GO) build -ldflags $(LDFLAGS) -o $(APPS4) $(GOFLAGS) ./ctl/main.go)

.PHONY: gen-proto
gen-proto:
	$(QUIET) make -C api gen-proto

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: gen
gen: tidy\
	gen-proto \
	format

.PHONY: gen-check
gen-check: gen
	hack/gen-check.sh

.PHONY: install
install:
	$(QUIET) make install -C api/v2-c
	$(QUIET) make install -C bpf/deserialization_to_bpf_map
	$(QUIET) make install -C kernel/ko_src

	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS1))
	$(QUIET) install -Dp -m 0500 $(APPS1) $(INSTALL_BIN)
	
	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS2))
	$(QUIET) install -Dp -m 0500 oncn-mda/deploy/$(APPS2) $(INSTALL_BIN)
	$(QUIET) install -Dp -m 0400 oncn-mda/build/ebpf_src/CMakeFiles/sock_ops.dir/sock_ops.c.o /usr/share/oncn-mda/sock_ops.c.o
	$(QUIET) install -Dp -m 0400 oncn-mda/build/ebpf_src/CMakeFiles/sock_redirect.dir/sock_redirect.c.o /usr/share/oncn-mda/sock_redirect.c.o

	$(call printlog, INSTALL, $(INSTALL_BIN)/$(APPS3))
	$(QUIET) install -Dp -m 0500 $(APPS3) $(INSTALL_BIN)

.PHONY: uninstall
uninstall:
	$(QUIET) make uninstall -C api/v2-c
	$(QUIET) make uninstall -C bpf/deserialization_to_bpf_map
	$(QUIET) make uninstall -C kernel/ko_src

	$(call printlog, UNINSTALL, $(INSTALL_BIN)/$(APPS1))
	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS1)
	$(call printlog, UNINSTALL, $(INSTALL_BIN)/$(APPS2))
	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS2)
	$(call printlog, UNINSTALL, $(INSTALL_BIN)/$(APPS3))
	$(QUIET) rm -rf $(INSTALL_BIN)/$(APPS3)

.PHONY: build
build:
	 VERSION=$(VERSION) ./kmesh_compile.sh

	# Build kmesh-daemon if included in BINARIES
	$(QUIET) ifneq ($(filter kmesh-daemon,$(BINARIES)),)
		$(call printlog, BUILD, $(APPS1))
		$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
			$(GO) build -ldflags $(LDFLAGS) -tags $(ENHANCED_KERNEL) -o $(APPS1) $(GOFLAGS) ./daemon/main.go)
	$(QUIET) endif

	# Build mdacore if included in BINARIES
	$(QUIET) ifneq ($(filter mdacore,$(BINARIES)),)
		$(call printlog, BUILD, $(APPS2))
		$(QUIET) cd oncn-mda && cmake . -B build && make -C build
	$(QUIET) endif

	# Build kmesh-cni if included in BINARIES
	$(QUIET) ifneq ($(filter kmesh-cni,$(BINARIES)),)
		$(call printlog, BUILD, $(APPS3))
		$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
			$(GO) build -ldflags $(LDFLAGS) -tags $(ENHANCED_KERNEL) -o $(APPS3) $(GOFLAGS) ./cniplugin/main.go)
	$(QUIET) endif

	# Build kmeshctl if included in BINARIES
	$(QUIET) ifneq ($(filter kmeshctl,$(BINARIES)),)
		$(call printlog, BUILD, $(APPS4))
		$(QUIET) (export PKG_CONFIG_PATH=$(PKG_CONFIG_PATH):$(ROOT_DIR)mk; \
			$(GO) build -ldflags $(LDFLAGS) -o $(APPS4) $(GOFLAGS) ./ctl/main.go)
	$(QUIET) endif

.PHONY: docker
docker: build
	docker build -f build/docker/dockerfile -t $(HUB)/$(TARGET):$(TAG) .

docker.push: docker
	docker push $(HUB)/$(TARGET):$(TAG)

.PHONY: e2e
e2e:
	./test/e2e/run_test.sh

.PHONY: e2e-ipv6
e2e-ipv6:
	./test/e2e/run_test.sh --ipv6

.PHONY: format
format:
	./hack/format.sh

.PHONY: test
ifeq ($(RUN_IN_CONTAINER),1)
test:
	./hack/run-ut.sh --docker
else
test:
	./hack/run-ut.sh --local
endif

.PHONY: clean
clean:
	$(QUIET) rm -rf ./out
	$(QUIET) rm -rf ./config/linux-bpf.h
	git checkout $(TMP_FILES)

	$(call printlog, CLEAN, $(APPS1))
	$(QUIET) rm -rf $(APPS1) $(APPS1)

	$(call printlog, CLEAN, $(APPS2))
	$(QUIET) rm -rf oncn-mda/build
	$(QUIET) rm -rf oncn-mda/deploy

	$(call printlog, CLEAN, $(APPS3))
	$(QUIET) rm -rf $(APPS1) $(APPS3)

	$(call printlog, CLEAN, $(APPS4))
	$(QUIET) rm -rf $(APPS1) $(APPS4)

	$(QUIET) make clean -C api/v2-c
	$(QUIET) make clean -C bpf/deserialization_to_bpf_map
	$(call printlog, CLEAN, "kernel")
	$(QUIET) make clean -C kernel/ko_src

	$(QUIET) if docker ps -a -q -f name=kmesh-build | grep -q .; then \
		docker rm -f kmesh-build; \
	fi


##@ Helm

CHARTS_FOLDER := deploy/charts
CHARTS := $(wildcard $(CHARTS_FOLDER)/*)
CHART_VERSION ?= v0.0.0-latest
CHART_OCI_REGISTRY ?= oci://$(HUB)
CHART_OUTPUT_DIR ?= out/charts

.PHONY: helm-package.%
helm-package.%: # Package Helm chart
	$(eval COMMAND := $(word 1,$(subst ., ,$*)))
	$(eval CHART_NAME := $(COMMAND))
	helm lint $(CHARTS_FOLDER)/${CHART_NAME}
	helm package $(CHARTS_FOLDER)/${CHART_NAME} --app-version ${VERSION} --version ${CHART_VERSION} --destination ${CHART_OUTPUT_DIR}/

.PHONY: helm-push.%
helm-push.%: helm-package.%
	$(eval COMMAND := $(word 1,$(subst ., ,$*)))
	$(eval CHART_NAME := $(COMMAND))
	helm push ${CHART_OUTPUT_DIR}/${CHART_NAME}-${CHART_VERSION}.tgz ${CHART_OCI_REGISTRY}

.PHONY: helm-package
helm-package:
	@for chart in $(CHARTS); do \
      	$(MAKE) $(addprefix helm-package., $$(basename $${chart})); \
	done

.PHONY: helm-push
helm-push: helm-package
	# run other make targets
	@for chart in $(CHARTS); do \
	  	$(MAKE) $(addprefix helm-push., $$(basename $${chart})); \
	done
