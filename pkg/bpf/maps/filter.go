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

// #cgo CFLAGS: -I../../../bpf/include
// #include "filter_type.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
)

// cFilter = C.filter_t
type cFilter struct {
	entry C.filter_t
}

type GoFilter struct {

}

func (f *GoFilter) toGolang(cf *cFilter) {
	return
}

func (f *GoFilter) toClang() *cFilter {
	return nil
}

func (f *GoFilter) Lookup(key *MapKey) error {
	cf := &cFilter{}
	err := bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Filter.
		Lookup(key, &cf.entry)

	if err == nil {
		f.toGolang(cf)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *f)

	return err
}

func (f *GoFilter) Update(key *MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *f)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Filter.
		Update(key, &f.toClang().entry, ebpf.UpdateAny)
}

func (f *GoFilter) Delete(key *MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *f)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Filter.
		Delete(key)
}

// cFilterChain = C.filter_chain_t
type cFilterChain struct {
	entry C.filter_chain_t
}

type GoFilterChain struct {

}

func (fc *GoFilterChain) toGolang(cfc *cFilterChain) {
	return
}

func (fc *GoFilterChain) toClang() *cFilterChain {
	return nil
}

func (fc *GoFilterChain) Lookup(key *MapKey) error {
	cfc := &cFilterChain{}
	err := bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.FilterChain.
		Lookup(key, &cfc.entry)

	if err == nil {
		fc.toGolang(cfc)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *fc)

	return err
}

func (fc *GoFilterChain) Update(key *MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *fc)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.FilterChain.
		Update(key, &fc.toClang().entry, ebpf.UpdateAny)
}

func (fc *GoFilterChain) Delete(key *MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *fc)
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.FilterChain.
		Delete(key)
}
