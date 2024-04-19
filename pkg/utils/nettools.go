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
package utils

import (
	"fmt"
	"net"
	"strings"
)

func Ifname2ifindex(ifname string) (int, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		err = fmt.Errorf("failed to get pod ifindex info, err is %v\n", err)
		return 0, err
	}
	for _, iface := range ifaces {
		if strings.Compare(iface.Name, ifname) == 0 {
			return iface.Index, nil
		}
	}
	return 0, fmt.Errorf("cann't to find interface:%v\n", ifname)
}
