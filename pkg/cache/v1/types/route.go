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

package types

// #cgo CFLAGS: -I../../../../bpf/include
// #include "route_type.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
)

// cRoute = C.route_t
type cRoute struct {
	entry C.route_t
}

type Route struct {

}

func (r *Route) toGolang(cr *cRoute) {
	return
}

func (r *Route) toClang() *cRoute {
	return nil
}

func (r *Route) Lookup(key *MapKey) error {
	cr := &cRoute{}
	err := bpf.Obj.SockConn.FilterObjects.FilterMaps.Route.
		Lookup(key, cr.entry)

	if err == nil {
		r.toGolang(cr)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *r)

	return err
}

func (r *Route) Update(key *MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *r)
	return bpf.Obj.SockConn.FilterObjects.FilterMaps.Route.
		Update(key, &r.toClang().entry, ebpf.UpdateAny)
}

func (r *Route) Delete(key *MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *r)
	return bpf.Obj.SockConn.FilterObjects.FilterMaps.Route.
		Delete(key)
}

// cVirtualHost = C.virtual_host_t
type cVirtualHost struct {
	entry C.virtual_host_t
}

type VirtualHost struct {

}

func (vh *VirtualHost) toGolang(cvh *cVirtualHost) {
	return
}

func (vh *VirtualHost) toClang() *cVirtualHost {
	return nil
}

func (vh *VirtualHost) Lookup(key *MapKey) error {
	cvh := &cVirtualHost{}
	err := bpf.Obj.SockConn.FilterObjects.FilterMaps.VirtualHost.
		Lookup(key, cvh.entry)

	if err == nil {
		vh.toGolang(cvh)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *vh)

	return err
}

func (vh *VirtualHost) Update(key *MapKey) error {
	log.Debugf("Update [%#v], [%#v]", *key, *vh)
	return bpf.Obj.SockConn.FilterObjects.FilterMaps.VirtualHost.
		Update(key, &vh.toClang().entry, ebpf.UpdateAny)
}

func (vh *VirtualHost) Delete(key *MapKey) error {
	log.Debugf("Delete [%#v], [%#v]", *key, *vh)
	return bpf.Obj.SockConn.FilterObjects.FilterMaps.VirtualHost.
		Delete(key)
}
