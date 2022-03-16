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

import (
	"github.com/cilium/ebpf"
	api_v1 "openeuler.io/mesh/api/v1"
	"openeuler.io/mesh/pkg/bpf"
	"openeuler.io/mesh/pkg/logger"
	"unsafe"
)

var (
	log = logger.NewLoggerField("cache/v1/maps")
)

func listenerToGolang(goMsg *api_v1.Listener, cMsg *api_v1.CListener) {
	memcpy(unsafe.Pointer(goMsg),
		unsafe.Pointer(&cMsg.Entry),
		unsafe.Sizeof(cMsg.Entry))
}

func listenerToClang(goMsg *api_v1.Listener) *api_v1.CListener {
	cl := &api_v1.CListener{}
	memcpy(unsafe.Pointer(&cl.Entry),
		unsafe.Pointer(goMsg),
		unsafe.Sizeof(cl.Entry))

	return cl
}

func ListenerLookup(key *api_v1.Address, value *api_v1.Listener) error {
	cMsg := &api_v1.CListener{}
	err := bpf.Obj.Slb.CgroupSockObjects.CgroupSockMaps.Listener.
		Lookup(key, cMsg.Entry)

	if err == nil {
		listenerToGolang(value, cMsg)
	}
	log.Debugf("Lookup [%#v], [%#v]", *key, *value)

	return err
}

func ListenerUpdate(key *api_v1.Address, value *api_v1.Listener) error {
	log.Debugf("Update [%#v], [%#v]", *key, *value)
	//todo xsy
	if err := bpf.Obj.XdpBalance.XdpBalanceObjects.XdpBalanceMaps.Listener.
		Update(key, &listenerToClang(value).Entry, ebpf.UpdateAny); err != nil {
		log.Errorf("Update xdp listener failed,[%#v], [%#v],err:%s", *key, *value, err)
	}
	return bpf.Obj.Slb.CgroupSockObjects.CgroupSockMaps.Listener.
		Update(key, &listenerToClang(value).Entry, ebpf.UpdateAny)
}

func ListenerDelete(key *api_v1.Address) error {
	log.Debugf("Delete [%#v]", *key)
	//todo xsy
	if err := bpf.Obj.XdpBalance.XdpBalanceObjects.XdpBalanceMaps.Listener.Delete(key); err != nil {
		log.Errorf("Delete xdp listener failed,[%#v],err:%s", *key, err)
	}
	return bpf.Obj.Slb.CgroupSockObjects.CgroupSockMaps.Listener.
		Delete(key)
}
