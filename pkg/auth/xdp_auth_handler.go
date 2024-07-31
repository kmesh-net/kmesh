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
	"fmt"

	"github.com/cilium/ebpf"
)

type notifyFunc func(mapOfAuth *ebpf.Map, msgType uint32, key []byte) error

func xdpNotifyConnRst(mapOfAuth *ebpf.Map, msgType uint32, key []byte) error {
	if mapOfAuth == nil {
		return fmt.Errorf("map_of_auth is nil")
	}
	// The last TUPLE_LEN-IPV4_TUPLE_LENGTH bytes should be filled with zeros if msgType is
	// MSG_TYPE_IPV4, so the key can be looked up successfully by XDP eBPF program
	if msgType == MSG_TYPE_IPV4 {
		for i := IPV4_TUPLE_LENGTH; i < len(key); i++ {
			key[i] = 0
		}
	}
	// Insert the socket tuple into the auth map, so xdp_auth_handler can know that socket with
	// this tuple is denied by policy, note that IP and port are big endian in auth map
	return mapOfAuth.Update(key, uint32(1), ebpf.UpdateAny)
}
