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
	serviceCount	uint32
	endpointsCount	uint32
	Service			*apiCoreV1.Service
	Endpoints		[]*apiCoreV1.Endpoints
}

type EventKey struct {
	opt		string
	name	string
}
/*
func NewEndpointFromKubernetes(ep *apiCoreV1.Endpoints) []maps.GoEndpoint {
	var endpoints []maps.GoEndpoint

	for _, sub := range ep.Subsets {
		// TODO: len(v.Subsets[]) > 1 ??
		for i := 0; i < len(sub.Addresses); i++ {
			goEndpoint := maps.GoEndpoint{}
			// TODO: goEndpoint.Address.Protocol = 0
			goEndpoint.Address.Port = uint32(sub.Ports[i].Port)
			goEndpoint.Address.IPv4 = maps.ConvertIpToUint32(sub.Addresses[i].IP)

			endpoints = append(endpoints, goEndpoint)
		}
	}

	return endpoints
}

func NewClusterFromKubernetes(ser *apiCoreV1.Service) *maps.GoCluster {

}

func NewListenerFromKubernetes(ser *apiCoreV1.Service) *maps.GoListener {

}*/

func (event *ClientEvent) Reset() {
	event.Service = nil
	event.Endpoints = nil
}

func (event *ClientEvent) Empty() bool {
	return (event.serviceCount == 0) && (event.endpointsCount == 0)
}

func (event *ClientEvent) EventHandler() error {
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
	return event.eventUpdateItem()
}

func (event *ClientEvent) eventUpdateItem() error {
	var (
		goEndpoint maps.GoEndpoint
		goCluster maps.GoCluster
		goListener maps.GoListener
	)

	mapKey := maps.GoMapKey{
		NameID: convert.StrToNum(event.Key.name),
		Index: event.endpointsCount,
	}

	// Update map of endpoint
	for _, ep := range event.Endpoints {
		log.Debugf("eventUpdateItem Endpoints: %#v", ep)
		log.Debug("---------")

		for _, sub := range ep.Subsets {
			// TODO: len(v.Subsets[]) > 1 ??
			for i := 0; i < len(sub.Addresses); i++ {
				goEndpoint = maps.GoEndpoint{}
				// TODO: goEndpoint.Address.Protocol = 0
				goEndpoint.Address.Port = uint32(sub.Ports[i].Port)
				goEndpoint.Address.IPv4 = maps.ConvertIpToUint32(sub.Addresses[i].IP)

				cEndpoint := goEndpoint.ToClang()
				if err := cEndpoint.Update(&mapKey); err != nil {
					log.Errorf("eventUpdateItem endpoint failed, %v, %s", mapKey, err)
					continue
				}
				mapKey.Index++
			}
		}
	}
	if event.Key.opt == InformerOptAdd {
		event.endpointsCount += mapKey.Index
	}

	if event.Service == nil {
		return nil
	}
	log.Debugf("eventUpdateItem server: %#v", event.Service)
	log.Debug("---------")

	mapKey.Index = 0
	// Update map of cluster
	goCluster.LoadAssignment.MapKeyOfEndpoint = mapKey
	goCluster.ConnectTimeout = 15

	cCluster := goCluster.ToClang()
	if err := cCluster.Update(&mapKey); err != nil {
		event.eventDeleteItem()
		return fmt.Errorf("eventUpdateItem cluster failed, %v, %s", mapKey, err)
	}

	// Update map of listener
	goListener.MapKey = mapKey
	goListener.Type = C.LISTENER_TYPE_DYNAMIC
	goListener.State = C.LISTENER_STATE_ACTIVE
	goListener.Address = maps.GoAddress{
		Protocol: 0,
		Port: uint32(event.Service.Spec.Ports[0].Port),
	}
	// TODO: support other type
	switch event.Service.Spec.Type {
	case apiCoreV1.ServiceTypeClusterIP:
		goListener.Address.IPv4 = maps.ConvertIpToUint32(event.Service.Spec.ClusterIP)
	case apiCoreV1.ServiceTypeNodePort:
	case apiCoreV1.ServiceTypeLoadBalancer:
	default:
	}

	cListener := goListener.ToClang()
	if err := cListener.Update(&goListener.Address); err != nil {
		event.eventDeleteItem()
		return fmt.Errorf("eventUpdateItem listener failed, %v, %s", goListener.Address, err)
	}

	if event.Key.opt == InformerOptAdd {
		event.serviceCount = 1
	}

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
