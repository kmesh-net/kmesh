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

package kubernetes

// #cgo CFLAGS: -I../../../bpf/include
// #include "listener_type.h"
import "C"
import (
	"fmt"
	apiCoreV1 "k8s.io/api/core/v1"
	"openeuler.io/mesh/pkg/bpf/maps"
)

var convert = maps.NewConvertMapKey()

type ClientEvent struct {
	Key			EventKey
	Service			*apiCoreV1.Service
	Endpoints		[]*apiCoreV1.Endpoints

	// k = endpointPort, v = count
	serviceCount	map[uint32]uint32
	// k = clusterPort, v = count
	endpointsCount	map[uint32]uint32
	// When you want to delete endpoint from the map,
	// you need to convert the address to key first.
	endpointsAddressToMapKey map[maps.GoAddress]maps.GoMapKey
}

type EventKey struct {
	opt		string
	name	string
}

var (
	ProtocolStrToC = map[apiCoreV1.Protocol]C.uint {
		apiCoreV1.ProtocolTCP:	0, //C.IPPROTO_TCP,
		apiCoreV1.ProtocolUDP:	6, //C.IPPROTO_UDP,
	}
)

func (event *ClientEvent) Init() {
	if event.serviceCount == nil {
		event.serviceCount = make(map[uint32]uint32)
	}
	if event.endpointsCount == nil {
		event.endpointsCount = make(map[uint32]uint32)
	}
	if event.endpointsAddressToMapKey == nil {
		event.endpointsAddressToMapKey = make(map[maps.GoAddress]maps.GoMapKey)
	}
}

func (event *ClientEvent) Reset() {
	event.Service = nil
	event.Endpoints = nil
}

func (event *ClientEvent) Empty() bool {
	for _, c := range event.serviceCount {
		if c > 0 {
			return true
		}
	}
	for _, c := range event.endpointsCount {
		if c > 0 {
			return true
		}
	}

	return false
}

func (event *ClientEvent) EventHandler() error {
	event.Init()

	switch event.Key.opt {
	case InformerOptAdd:
		return event.eventAddItem()
	case InformerOptUpdate:
		return event.eventUpdateItem()
	case InformerOptDelete:
		return event.eventDeleteItem()
	default:
		return fmt.Errorf("EventHandler get invalid informer opt")
	}
}

func (event *ClientEvent) eventAddItem() error {
	var (
		goEndpoint maps.GoEndpoint
		goCluster maps.GoCluster
		goListener maps.GoListener
		mapKey maps.GoMapKey
	)

	mapKey.NameID = convert.StrToNum(event.Key.name)

	// Update map of endpoint
	for _, ep := range event.Endpoints {
		log.Debugf("eventUpdateItem Endpoints: %#v", ep)
		log.Debug("------------------")

		for _, sub := range ep.Subsets {
			for _, epPort := range sub.Ports {
				goEndpoint.Address.Port = uint32(epPort.Port)
				mapKey.Port = goEndpoint.Address.Port
				mapKey.Index = event.endpointsCount[mapKey.Port]

				for _, epAddr := range sub.Addresses {
					goEndpoint.Address.Protocol = ProtocolStrToC[epPort.Protocol]
					goEndpoint.Address.IPv4 = maps.ConvertIpToUint32(epAddr.IP)

					cEndpoint := goEndpoint.ToClang()
					if err := cEndpoint.Update(&mapKey); err != nil {
						log.Errorf("eventUpdateItem endpoint failed, %v, %s", mapKey, err)
						continue
					}

					event.endpointsAddressToMapKey[goEndpoint.Address] = mapKey
					mapKey.Index++
				}

				event.endpointsCount[mapKey.Port] = mapKey.Index
			}
		}
	}

	if event.Service == nil {
		return nil
	}
	log.Debugf("eventUpdateItem server: %#v", event.Service)
	log.Debug("------------------")

	// Update map of cluster
	// TODO
	//goCluster.Type = 0
	//goCluster.ConnectTimeout = 15

	mapKey.Index = 0
	for _, serPort := range event.Service.Spec.Ports {
		mapKey.Port = uint32(serPort.TargetPort.IntVal)
		goCluster.LoadAssignment.MapKeyOfEndpoint = mapKey

		mapKey.Port = uint32(serPort.Port)
		cCluster := goCluster.ToClang()
		if err := cCluster.Update(&mapKey); err != nil {
			event.eventDeleteItem()
			return fmt.Errorf("eventUpdateItem cluster failed, %v, %s", mapKey, err)
		}

		event.serviceCount[mapKey.Port] = 1
	}

	// Update map of listener
	goListener.MapKey = mapKey
	goListener.Type = C.LISTENER_TYPE_DYNAMIC
	goListener.State = C.LISTENER_STATE_ACTIVE

	for _, serPort := range event.Service.Spec.Ports {
		goListener.Address.Protocol = ProtocolStrToC[serPort.Protocol]

		// apiCoreV1.ServiceTypeClusterIP
		goListener.Address.IPv4 = maps.ConvertIpToUint32(event.Service.Spec.ClusterIP)
		goListener.Address.Port = uint32(serPort.Port)

		goListener.MapKey.Port = uint32(serPort.TargetPort.IntVal)

		cListener := goListener.ToClang()
		if err := cListener.Update(&goListener.Address); err != nil {
			event.eventDeleteItem()
			return fmt.Errorf("eventUpdateItem listener failed, %v, %s", goListener.Address, err)
		}

		// apiCoreV1.ServiceTypeNodePort
		if event.Service.Spec.Type == apiCoreV1.ServiceTypeNodePort {
			goListener.Address.IPv4 = 0
			goListener.Address.Port = uint32(serPort.NodePort)

			cListener := goListener.ToClang()
			if err := cListener.Update(&goListener.Address); err != nil {
				event.eventDeleteItem()
				return fmt.Errorf("eventUpdateItem listener failed, %v, %s", goListener.Address, err)
			}
		}
	}

	return nil
}

func (event *ClientEvent) eventUpdateItem() error {
	return nil
}

func (event *ClientEvent) eventDeleteItem() error {
	//log.Debugf("syncHandler for Endpoints: %#v", obj)
	//fmt.Println("")
	return nil
	// FIXME: update map flags??
	// FIXME: 没有收到删除事件
	// FIXME: 怎么去得到key，遍历？
}
