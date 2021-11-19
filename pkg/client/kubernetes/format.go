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

import "C"
import (
	"fmt"
	apiCoreV1 "k8s.io/api/core/v1"
	"openeuler.io/mesh/pkg/bpf/maps"
)

var convert = maps.ConvertMapKey{}

type ClientEvent struct {
	QKey	queueKey
	Service		*apiCoreV1.Service
	Endpoints	[]*apiCoreV1.Endpoints
}

func (event *ClientEvent) EventHandler() error {
	switch event.QKey.opt {
	case InformerOptUpdate:
		return event.eventUpdateItem()
	case InformerOptDelete:
		return event.eventDeleteItem()
	default:
		return nil
	}
}

func (event *ClientEvent) eventUpdateItem() error {
	var (
		goEndpoint maps.GoEndpoint
		goCluster maps.GoCluster
		goListener maps.GoListener
	)

	key := maps.GoMapKey{
		NameID: convert.StrToNum(event.QKey.name),
		Index: 0,
	}

	// Update map of endpoint
	for _, v := range event.Endpoints {
		log.Debugf("eventUpdateItem Endpoints: %#v", v)
		fmt.Println("")
		// TODO: len(v.Subsets[]) > 1 ??
		for i := 0; i < len(v.Subsets[0].Addresses); i++ {
			goEndpoint = maps.GoEndpoint{}
			// TODO: goEndpoint.Address.Protocol =
			goEndpoint.Address.Port = uint32(v.Subsets[0].Ports[i].Port)
			goEndpoint.Address.IPv4 = maps.ConvertIpToUint32(v.Subsets[0].Addresses[i].IP)

			cEndpoint := goEndpoint.ToClang()
			if err := cEndpoint.Update(&key); err != nil {
				// TODO: failed
				fmt.Printf("eventUpdateItem endpoint failed, %s\n", err)
			}
			key.Index++
		}
	}

	// Update map of cluster
	log.Debugf("eventUpdateItem server: %#v", event.Service)
	fmt.Println("")
	// TODO: goCluster.Type = C.CLUSTER_TYPE_STATIC
	goCluster.ConnectTimeout = 15
	goCluster.LoadAssignment.MapKeyOfEndpoint = key

	cCluster := goCluster.ToClang()
	key.Index = 1
	if err := cCluster.Update(&key); err != nil {
		// TODO: failed
		fmt.Printf("eventUpdateItem cluster failed, %s\n", err)
	}

	// Update map of listener
	goListener.MapKey = key
	goListener.Type = C.LISTENER_TYPE_DYNAMIC
	goListener.State = C.LISTENER_STATE_ACTIVE
	goListener.Address = maps.GoAddress{
		Protocol: 0,
		Port: uint32(event.Service.Spec.Ports[0].Port),
		// TODO: event.Service.Spec.Type
		IPv4: maps.ConvertIpToUint32(event.Service.Spec.ClusterIP),
	}

	cListener := goListener.ToClang()
	if err := cListener.Update(&goListener.Address); err != nil {
		// TODO: failed
		fmt.Printf("eventUpdateItem listener failed, %s\n", err)
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
