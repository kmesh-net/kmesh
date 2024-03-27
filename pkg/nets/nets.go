/*
 * Copyright 2023 The Kmesh Authors.
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

 * Author: LemmyHuang
 * Create: 2021-12-07
 */

// Package nets : net connection provider
package nets

import (
	"encoding/binary"
	"net"
)

// ConvertIpToUint32 converts ip to little-endian uint32 format
func ConvertIpToUint32(ip string) uint32 {
	netIP := net.ParseIP(ip) // BigEndian
	if len(netIP) == net.IPv6len {
		return binary.LittleEndian.Uint32(netIP.To4())
	}
	return binary.LittleEndian.Uint32(netIP)
}

// ConvertUint32ToIp converts big-endian uint32 to ip format
func ConvertUint32ToIp(big uint32) string {
	netIP := make(net.IP, 4)
	binary.LittleEndian.PutUint32(netIP, big)
	return netIP.String()
}

// ConvertPortToBigEndian convert uint32 to network order
func ConvertPortToBigEndian(little uint32) uint32 {
	// first convert to uint16, then convert the byte order,
	// finally switch back to uint32
	tmp := make([]byte, 2)
	little16 := uint16(little)
	binary.BigEndian.PutUint16(tmp, little16)
	big16 := binary.LittleEndian.Uint16(tmp)
	return uint32(big16)
}

// ConvertIpByteToUint32 converts ip to little-endian uint32 format
func ConvertIpByteToUint32(ip []byte) uint32 {
	return binary.LittleEndian.Uint32(ip)
}
