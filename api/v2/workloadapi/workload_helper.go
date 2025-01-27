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

package workloadapi

// ResourceName returns the unique key of Workload.
func (x *Workload) ResourceName() string {
	return x.Uid
}

// ResourceName returns the unique key of Service.
func (x *Service) ResourceName() string {
	return x.Namespace + "/" + x.Hostname
}

// GetIpAddress returns the address in service.addresses.
func (x *Service) GetIpAddresses() [][]byte {
	addresses := x.GetAddresses()
	if addresses == nil {
		return nil
	}
	var ipByte [][]byte
	for _, address := range addresses {
		ipByte = append(ipByte, address.Address)
	}
	return ipByte
}
