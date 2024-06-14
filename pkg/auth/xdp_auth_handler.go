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

package auth

import (
	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/pkg/utils"
)

const (
	XDP_AUTH_MAP_NAME = "map_of_auth"
)

type bpfSockTupleV4 struct {
	SrcAddr uint32
	DstAddr uint32
	SrcPort uint16
	DstPort uint16
}

type bpfSockTupleV6 struct {
	SrcAddr [4]uint32
	DstAddr [4]uint32
	SrcPort uint16
	DstPort uint16
}

type xdpHandlerKeyV4 struct {
	Tuple  bpfSockTupleV4
	Filled [24]byte
}

type xdpHandlerKeyV6 struct {
	tuple bpfSockTupleV6
}

func xdpNotifyConnRstV4(key *xdpHandlerKeyV4) error {
	log.Infof("XdpHandlerUpdateV4 [%#v]", *key)
	var (
		authMap *ebpf.Map
		err     error
	)
	if authMap, err = utils.GetMapByName(XDP_AUTH_MAP_NAME); err != nil {
		log.Errorf("GetMapByName in XdpHandlerUpdateV4 FAILED, err: %v", err)
		return err
	}
	// Insert the socket tuple into the auth map, so xdp_auth_handler can know that socket with
	// this tuple is denied by policy
	return authMap.Update(key, uint32(1), ebpf.UpdateAny)
}

func xdpNotifyConnRstV6(key *xdpHandlerKeyV6) error {
	log.Infof("XdpHandlerUpdateV6 [%#v]", *key)
	var (
		authMap *ebpf.Map
		err     error
	)
	if authMap, err = utils.GetMapByName(XDP_AUTH_MAP_NAME); err != nil {
		log.Errorf("GetMapByName in XdpHandlerUpdateV6 FAILED, err: %v", err)
		return err
	}
	// Insert the socket tuple into the auth map, so xdp_auth_handler can know that socket with
	// this tuple is denied by policy
	return authMap.Update(key, uint32(1), ebpf.UpdateAny)
}

func clearAuthInitStateV4(key *xdpHandlerKeyV4) error {
	var (
		authMap *ebpf.Map
		err     error
	)
	if authMap, err = utils.GetMapByName(XDP_AUTH_MAP_NAME); err != nil {
		log.Errorf("GetMapByName in clearAuthInitStateV6 failed, err: %v", err)
		return err
	}
	return authMap.Delete(key)
}

func clearAuthInitStateV6(key *xdpHandlerKeyV6) error {
	var (
		authMap *ebpf.Map
		err     error
	)
	if authMap, err = utils.GetMapByName(XDP_AUTH_MAP_NAME); err != nil {
		log.Errorf("GetMapByName in clearAuthInitStateV6 failed, err: %v", err)
		return err
	}
	return authMap.Delete(key)
}
