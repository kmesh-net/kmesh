/*
 * Copyright 2024 The Kmesh Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bpf

import (
	"github.com/cilium/ebpf"
	"kmesh.net/kmesh/pkg/controller/common/types"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	XDP_AUTH_MAP_NAME = "map_of_auth"
)

var (
	log = logger.NewLoggerField("controller/bpf")
)

type XdpHandlerKeyV4 struct {
	Tuple  types.BpfSockTupleV4
	Filled [24]byte
}

type XdpHandlerKeyV6 struct {
	Tuple types.BpfSockTupleV6
}

func XdpHandlerUpdateV4(key *XdpHandlerKeyV4) error {
	log.Infof("XdpHandlerUpdateV4 [%#v]", *key)
	var (
		authMap *ebpf.Map
		err     error
	)
	if authMap, err = utils.GetMapByName(XDP_AUTH_MAP_NAME); err != nil {
		log.Errorf("GetMapByName in XdpHandlerUpdateV4 FAILED, err: %v", err)
		return err
	}
	return authMap.Update(key, uint32(1), ebpf.UpdateAny)
}

func XdpHandlerUpdateV6(key *XdpHandlerKeyV6) error {
	log.Infof("XdpHandlerUpdateV6 [%#v]", *key)
	var (
		authMap *ebpf.Map
		err     error
	)
	if authMap, err = utils.GetMapByName(XDP_AUTH_MAP_NAME); err != nil {
		log.Errorf("GetMapByName in XdpHandlerUpdateV6 FAILED, err: %v", err)
		return err
	}
	return authMap.Update(key, uint32(1), ebpf.UpdateAny)
}
