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

package factory

import "github.com/cilium/ebpf"

type GlobalBpfConfig struct {
	BpfLogLevel      uint32
	NodeIP           [16]byte
	PodGateway       [16]byte
	AuthzOffload     uint32
	EnableMonitoring uint32
}

type KmeshBpfConfig struct {
	BpfLogLevel      *ebpf.Variable
	NodeIP           *ebpf.Variable
	PodGateway       *ebpf.Variable
	AuthzOffload     *ebpf.Variable
	EnableMonitoring *ebpf.Variable
}
