/*
 * Copyright The Kmesh Authors.
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

// Package nets : net connection provider
package nets

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("nets")

// ConvertIpToUint32 converts ip to little-endian uint32 format
func ConvertIpToUint32(ip string) uint32 {
	netIP := net.ParseIP(ip) // BigEndian
	if netIP == nil {
		return 0
	}
	// TODO: is this right?
	if len(netIP) == net.IPv6len {
		return binary.LittleEndian.Uint32(netIP.To4())
	}
	if len(netIP) == net.IPv4len {
		return binary.LittleEndian.Uint32(netIP)
	}
	return 0
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

// ConvertPortToLittleEndian convert port to host order
func ConvertPortToLittleEndian(big uint32) uint32 {
	tmp := make([]byte, 2)
	binary.LittleEndian.PutUint16(tmp, uint16(big))
	little16 := binary.BigEndian.Uint16(tmp)
	return uint32(little16)
}

func CopyIpByteFromSlice(dst *[16]byte, src []byte) {
	len := len(src)
	if len != 4 && len != 16 {
		return
	}
	copy(dst[:], src)
}

// IpString converts ip bytes to string, for IpV4, it checks
// whether the last 12 bytes are all zeros.
// TODO: this may conflict with IpV6 addresses with the same pattern,
// we should find a better way to indicate the ipv4 address.
func IpString(ip [16]byte) string {
	if isZeros(ip[5:]) {
		return net.IP(ip[:4]).String()
	}
	return net.IP(ip[:]).String()
}

func isZeros(p []byte) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}

func checkIPVersion() (ipv4, ipv6 bool) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false, false
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() {
			continue
		}

		if ip := ipnet.IP; ip != nil {
			if ip.To4() != nil {
				ipv4 = true
			} else if ip.To16() != nil {
				ipv6 = true
			}
		}
	}

	return ipv4, ipv6
}

// Compare two slices and return the data added to a over b and the data missing from b over a.
//
// Args:
//
//	a: new data
//	b: old data
//
// return:
//
//	    Add: the data added to a over b
//		Remove: the data missing from b over a
//
// TODO: Optimising functions to be able to handle different data types
func CompareIpByte(a, b [][]byte) [][]byte {
	aSet := make(map[string][]byte)
	for _, item := range a {
		ip, ok := netip.AddrFromSlice(item)
		if !ok {
			log.Error("cannot compared IP: Unsupported data types")
		}

		aSet[ip.String()] = item
	}

	var bMissing [][]byte
	for _, item := range b {
		ip, ok := netip.AddrFromSlice(item)
		if !ok {
			log.Error("cannot compared IP: Unsupported data types")
		}
		if _, ok := aSet[ip.String()]; !ok {
			bMissing = append(bMissing, item)
		} else {
			delete(aSet, ip.String())
		}
	}

	return bMissing
}

func triggerControlCommandWithPortInV4(port int) error {
	ip := net.ParseIP(constants.ControlCommandIp4)
	sockfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(sockfd)

	if err = syscall.SetNonblock(sockfd, true); err != nil {
		return err
	}
	err = syscall.Connect(sockfd, &syscall.SockaddrInet4{
		Port: port,
		Addr: [4]byte(ip.To4()),
	})
	if err == nil {
		return err
	}
	errno, ok := err.(syscall.Errno)
	if ok && errno == syscall.EINPROGRESS { // -EINPROGRESS, Operation now in progress
		return nil
	}
	return err
}

func triggerControlCommandWithPortInV6(port int) error {
	ip := net.ParseIP(constants.ControlCommandIp6)
	sockfd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(sockfd)

	if err = syscall.SetNonblock(sockfd, true); err != nil {
		return err
	}
	err = syscall.Connect(sockfd, &syscall.SockaddrInet6{
		Port: port,
		Addr: [16]byte(ip.To16()),
	})
	if err == nil {
		return err
	}
	errno, ok := err.(syscall.Errno)
	if ok && errno == syscall.EINPROGRESS { // -EINPROGRESS, Operation now in progress
		return nil
	}
	return err
}

func TriggerControlCommand(oper int) error {
	ipv4, ipv6 := checkIPVersion()
	if ipv4 {
		return triggerControlCommandWithPortInV4(oper)
	}
	if ipv6 {
		return triggerControlCommandWithPortInV6(oper)
	}
	return nil
}
