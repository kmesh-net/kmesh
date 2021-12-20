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

import (
	"fmt"
	apiCoreV1 "k8s.io/api/core/v1"
	"openeuler.io/mesh/pkg/bpf/maps"
	"openeuler.io/mesh/pkg/nets"
	"openeuler.io/mesh/pkg/option"
)

type clusterKeyAndValue struct {
	key		maps.GoMapKey
	value	maps.GoCluster
}
type clusterData map[clusterKeyAndValue]objOptionFlag

func (data clusterData) deleteInvalid(kv *clusterKeyAndValue) {
	if data[*kv] == serviceOptionAllFlag {
		delete(data, *kv)
	}
}

func (data clusterData) extractData(flag objOptionFlag, svc *apiCoreV1.Service, nameID uint32) {
	var kv clusterKeyAndValue

	if svc == nil {
		return
	}

	kv.key.NameID = nameID
	kv.value.LoadAssignment.MapKeyOfEndpoint.NameID = nameID
	// TODO
	kv.value.Type = 0
	kv.value.ConnectTimeout = 15

	for _, serPort := range svc.Spec.Ports {
		if !option.EnabledProtocolConfig(string(serPort.Protocol)) {
			continue
		}

		kv.value.LoadAssignment.MapKeyOfEndpoint.Port = nets.ConvertPortToLittleEndian(serPort.TargetPort.IntVal)
		kv.key.Port = nets.ConvertPortToLittleEndian(serPort.Port)

		data[kv] |= flag
		data.deleteInvalid(&kv)
	}
}

func (data clusterData) flushMap(flag objOptionFlag, count objCount) int {
	var err error
	var num int

	for kv, f := range data {
		if f != flag {
			continue
		}

		switch flag {
		case serviceOptionDeleteFlag:
			err = kv.deleteMap(count)
		case serviceOptionUpdateFlag:
			err = kv.updateMap(count)
		default:
			// ignore
		}
		num++

		if err != nil {
			log.Errorln(err)
		}
	}

	return num
}

func (kv *clusterKeyAndValue) updateMap(count objCount) error {
	cCluster := kv.value.ToClang()
	if err := cCluster.Update(&kv.key); err != nil {
		return fmt.Errorf("update cluster failed, %v, %s", kv.value, err)
	}

	count[kv.key.Port] = 1
	return nil
}

func (kv *clusterKeyAndValue) deleteMap(count objCount) error {
	cCluster := &maps.CCluster{}
	if err := cCluster.Delete(&kv.key); err != nil {
		return fmt.Errorf("delete cluster failed, %v, %s", kv.key, err)
	}

	delete(count, kv.key.Port)
	return nil
}
