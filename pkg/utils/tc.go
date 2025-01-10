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

package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"kmesh.net/kmesh/pkg/constants"
)

func ManageTCProgramByFd(link netlink.Link, tcFd int, mode int) error {
	if mode == constants.TC_ATTACH {
		if err := replaceQdisc(link); err != nil {
			return fmt.Errorf("failed to replace qdisc for interface %v: %v", link.Attrs().Name, err)
		}
	}

	var parent uint32 = netlink.HANDLE_MIN_INGRESS
	var tcName string = "tc_ingress"
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  1,
		},
		Fd:           tcFd,
		Name:         fmt.Sprintf("%s-%s", tcName, link.Attrs().Name),
		DirectAction: true,
	}

	if mode == constants.TC_ATTACH {
		if err := netlink.FilterReplace(filter); err != nil {
			return fmt.Errorf("failed to replace filter for interface %v: %v", link.Attrs().Name, err)
		}
	} else if mode == constants.TC_DETACH {
		if err := netlink.FilterDel(filter); err != nil {
			return fmt.Errorf("failed to delete filter for interface %v: %v", link.Attrs().Name, err)
		}
	} else {
		return fmt.Errorf("invalid mode in ManageTCProgramByFd")
	}
	return nil
}

func ManageTCProgram(link netlink.Link, tc *ebpf.Program, mode int) error {
	return ManageTCProgramByFd(link, tc.FD(), mode)
}

func replaceQdisc(link netlink.Link) error {
	attrs := netlink.QdiscAttrs{
		LinkIndex: link.Attrs().Index,
		Handle:    netlink.MakeHandle(0xffff, 0),
		Parent:    netlink.HANDLE_CLSACT,
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: attrs,
		QdiscType:  "clsact",
	}

	return netlink.QdiscReplace(qdisc)
}

func GetVethPeerIndexFromName(ifaceName string) (uint64, error) {
	var ifIndex uint64
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return 0, err
	}
	defer ethHandle.Close()
	if driver, err := ethHandle.DriverName(ifaceName); err != nil {
		return 0, fmt.Errorf("failed to get %v driver name, %v", ifaceName, err)
	} else if strings.Compare(driver, "veth") != 0 {
		return 0, fmt.Errorf("interface: %v is %v, not a veth", ifaceName, driver)
	}

	if stats, err := ethHandle.Stats(ifaceName); err != nil {
		return 0, fmt.Errorf("failed to get %v stats, %v", ifaceName, err)
	} else {
		ifIndex = stats["peer_ifindex"]
	}
	return ifIndex, nil
}

func GetVethPeerIndexFromInterface(iface net.Interface) (uint64, error) {
	if iface.Flags&net.FlagLoopback != 0 {
		return 0, fmt.Errorf("interface: %v is a local interface", iface)
	}

	if iface.Flags&net.FlagUp == 0 {
		return 0, fmt.Errorf("interface: %v not up", iface)
	}

	return GetVethPeerIndexFromName(iface.Name)
}

func IfaceContainIPs(iface net.Interface, IPs []string) (bool, error) {
	addresses, err := iface.Addrs()
	if err != nil {
		return false, fmt.Errorf("failed to get interface %v address: %v", iface.Name, err)
	}

	for _, rawAddr := range addresses {
		addr, ok := rawAddr.(*net.IPNet)
		if !ok {
			log.Warnf("failed to convert ifaddr %v, %v", rawAddr, err)
			continue
		}
		for _, rawLocalAddr := range IPs {
			localAddr := net.ParseIP(rawLocalAddr)
			if addr.IP.Equal(localAddr) {
				return true, nil
			}
		}
	}
	return false, nil
}
