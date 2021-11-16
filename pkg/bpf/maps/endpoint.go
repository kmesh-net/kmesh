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
// #include "endpoint.h"
import "C"
import (
	"github.com/cilium/ebpf"
	"openeuler.io/mesh/pkg/bpf"
)

// ClangEndpoint = C.endpoint_t
type ClangEndpoint struct {
	Entry	C.endpoint_t
}

func (ce *ClangEndpoint) Lookup(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Endpoint.
		Lookup(key, &ce.Entry)
}

func (ce *ClangEndpoint) Update(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Endpoint.
		Update(key, &ce.Entry, ebpf.UpdateAny)
}

func (ce *ClangEndpoint) Delete(key *MapKey) error {
	return bpf.Obj.SockConn.CgroupSockObjects.CgroupSockMaps.Endpoint.
		Delete(key)
}

type Endpoint struct {

}

func (ce *ClangEndpoint) ToGolang() *Endpoint {
	return nil
}

func (e *Endpoint) ToClang() *ClangEndpoint {
	return nil
}
