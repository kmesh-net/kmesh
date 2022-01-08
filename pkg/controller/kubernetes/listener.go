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
 * Create: 2021-12-22
 */

package kubernetes

// #cgo CFLAGS: -I../../../bpf/include
// #include "listener_type.h"
import "C"
import (
	"fmt"
	apiCoreV1 "k8s.io/api/core/v1"
	"openeuler.io/mesh/pkg/bpf/maps"
	"openeuler.io/mesh/pkg/nets"
)

type listenerKeyAndValue struct {
	key		maps.Address
	value	maps.Listener
}
type listenerData map[listenerKeyAndValue]objOptionFlag

func (data listenerData) deleteInvalid(kv *listenerKeyAndValue) {
	if data[*kv] == serviceOptionAllFlag {
		delete(data, *kv)
	}
}

func (data listenerData) extractData(svcFlag objOptionFlag, svc *apiCoreV1.Service,
	addr nodeAddress, nameID uint32) {
	var kv listenerKeyAndValue

	if svc == nil {
		return
	}

	kv.value.MapKey.NameID = nameID
	kv.value.Type = C.LISTENER_TYPE_DYNAMIC
	kv.value.State = C.LISTENER_STATE_ACTIVE

	for _, serPort := range svc.Spec.Ports {
		if !nets.GetConfig().IsEnabledProtocol(string(serPort.Protocol)) {
			continue
		}

		// TODO: goListener.Address.Protocol = ProtocolStrToC[serPort.Protocol]
		kv.value.MapKey.Port = nets.ConvertPortToLittleEndian(serPort.Port)

		switch svc.Spec.Type {
		case apiCoreV1.ServiceTypeNodePort:
			kv.key.Port = nets.ConvertPortToLittleEndian(serPort.NodePort)
			for ip, nodeFlag := range addr {
				kv.key.IPv4 = nets.ConvertIpToUint32(ip)
				kv.value.Address = kv.key

				if svcFlag != 0 {
					data[kv] |= svcFlag
				} else if nodeFlag != 0 {
					data[kv] |= nodeFlag
				}
				data.deleteInvalid(&kv)
			}
			fallthrough
		case apiCoreV1.ServiceTypeClusterIP:
			if svcFlag != 0 {
				kv.key.Port = nets.ConvertPortToLittleEndian(serPort.Port)
				// TODO: Service.Spec.ExternalIPs ??
				kv.key.IPv4 = nets.ConvertIpToUint32(svc.Spec.ClusterIP)

				kv.value.Address = kv.key
				data[kv] |= svcFlag
				data.deleteInvalid(&kv)
			}
		case apiCoreV1.ServiceTypeLoadBalancer:
			// TODO
		case apiCoreV1.ServiceTypeExternalName:
			// TODO
		default:
			// ignore
		}
	}
}

func (data listenerData) flushMap(flag objOptionFlag) int {
	var err error
	var num int

	for kv, f := range data {
		if f != flag {
			continue
		}

		switch flag {
		case serviceOptionDeleteFlag:
			err = kv.deleteMap()
		case serviceOptionUpdateFlag:
			err = kv.updateMap()
		default:
			// ignore
		}

		if err != nil {
			log.Errorln(err)
		}
	}

	return num
}

func (kv *listenerKeyAndValue) updateMap() error {
	if err := kv.value.Update(&kv.key); err != nil {
		return fmt.Errorf("update listener failed, %v, %s", kv.key, err)
	}
	return nil
}

func (kv *listenerKeyAndValue) deleteMap() error {
	if err := kv.value.Delete(&kv.key); err != nil {
		return fmt.Errorf("delete listener failed, %v, %s", kv.key, err)
	}
	return nil
}
