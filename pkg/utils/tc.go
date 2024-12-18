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

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func AttchTCProgram(link netlink.Link, tc *ebpf.Program) error {
	if err := replaceQdisc(link); err != nil {
		return fmt.Errorf("failed to replace qdisc for interface %v: %v", link.Attrs().Name, err)
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
		Fd:           tc.FD(),
		Name:         fmt.Sprintf("%s-%s", tcName, link.Attrs().Name),
		DirectAction: true,
	}
	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("failed to replace filter for interface %v: %v", link.Attrs().Name, err)
	}
	return nil
}

func DetchTCProgram(link netlink.Link, tc *ebpf.Program) error {
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
		Fd:           tc.FD(),
		Name:         fmt.Sprintf("%s-%s", tcName, link.Attrs().Name),
		DirectAction: true,
	}
	if err := netlink.FilterDel(filter); err != nil {
		return fmt.Errorf("failed to replace filter for interface %v: %v", link.Attrs().Name, err)
	}
	return nil
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
