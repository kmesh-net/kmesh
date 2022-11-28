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
 * Create: 2021-12-07
 */

// Package nets : net connection provider
package nets

import (
	"encoding/binary"
	"net"
)

// ConvertIpToUint32 converts ip to little endian uint32 format
func ConvertIpToUint32(ip string) uint32 {
	netIP := net.ParseIP(ip)
	if len(netIP) == net.IPv6len {
		return binary.LittleEndian.Uint32(netIP.To4())
	}
	return binary.LittleEndian.Uint32(netIP)
}

// ConvertUint32ToIp converts uint32 to ip format
func ConvertUint32ToIp(num uint32) string {
	netIP := make(net.IP, 4)
	binary.LittleEndian.PutUint32(netIP, num)
	return netIP.String()
}

// ConvertPortToLittleEndian is the little-endian implementation of ByteOrder.
func ConvertPortToLittleEndian(num uint32) uint32 {
	// FIXME
	tmp := make([]byte, 2)
	big16 := uint16(num)
	binary.BigEndian.PutUint16(tmp, big16)
	little16 := binary.LittleEndian.Uint16(tmp)
	return uint32(little16)
}
