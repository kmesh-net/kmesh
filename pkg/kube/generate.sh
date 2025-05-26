#!/usr/bin/env bash

controller-gen crd paths=./... output:crd:dir=../../deploy/yaml/crd

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE[0]}")/../../
CODEGEN_PKG=${CODEGEN_PKG:-$(
	cd "${SCRIPT_ROOT}"
	ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../../../code-generator
)}
KUBE_VERBOSE=9

source "${CODEGEN_PKG}/kube_codegen.sh"

THIS_PKG="kmesh.net/kmesh"

kube::codegen::gen_helpers \
	--boilerplate "${SCRIPT_ROOT}/pkg/kube/boilerplate.go.txt" \
	"${SCRIPT_ROOT}/pkg/kube/apis"

kube::codegen::gen_client \
	--with-watch \
	--output-dir "${SCRIPT_ROOT}/pkg/kube/nodeinfo" \
	--output-pkg "${THIS_PKG}/pkg/kube/nodeinfo" \
	--boilerplate "${SCRIPT_ROOT}/pkg/kube/boilerplate.go.txt" \
	"${SCRIPT_ROOT}/pkg/kube/apis"
