/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-10-09
 */

package maps

// #cgo CFLAGS: -I../../bpf/include
// #include "filter.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
)

// ClangFilter = C.filter_t
type ClangFilter struct {
	Entry	C.filter_t
}

func (cf *ClangFilter) Lookup(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Filter.
		Lookup(key, &cf.Entry)
}

func (cf *ClangFilter) Update(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Filter.
		Update(key, &cf.Entry, ebpf.UpdateAny)
}

func (cf *ClangFilter) Delete(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Filter.
		Delete(key)
}

type Filter struct {

}

func (cf *ClangFilter) ToGolang() *Filter {
	return nil
}

func (f *Filter) ToClang() *ClangFilter {
	return nil
}

// ClangFilterChain = C.filter_chain_t
type ClangFilterChain struct {
	Entry	C.filter_chain_t
}

func (cfc *ClangFilterChain) Lookup(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.FilterChain.
		Lookup(key, &cfc.Entry)
}

func (cfc *ClangFilterChain) Update(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.FilterChain.
		Update(key, &cfc.Entry, ebpf.UpdateAny)
}

func (cfc *ClangFilterChain) Delete(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.FilterChain.
		Delete(key)
}

type FilterChain struct {

}

func (cfc *ClangFilterChain) ToGolang() *FilterChain {
	return nil
}

func (fc *FilterChain) ToClang() *ClangFilterChain {
	return nil
}
