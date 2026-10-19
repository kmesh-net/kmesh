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

package mcp

// BpfMapDumpRequest defines the input schema for the get_bpf_maps tool.
type BpfMapDumpRequest struct {
	PodName   string `json:"podName,omitempty" jsonschema:"description=Target daemon pod name (auto-discovered if empty)"`
	Namespace string `json:"namespace,omitempty" jsonschema:"description=Target daemon pod namespace (default: kmesh-system)"`
	Mode      string `json:"mode,omitempty" jsonschema:"description=Operating mode (kernel-native or dual-engine, auto-detected if empty)"`
	Summary   bool   `json:"summary,omitempty" jsonschema:"description=Return counts and compact identities instead of the full dump (default: true)"`
	Filter    string `json:"filter,omitempty" jsonschema:"description=Case-insensitive substring matched against entry name/IP/UID"`
}

type GetVersionRequest struct {
	PodName   string `json:"podName,omitempty" jsonschema:"description=Optional kmesh-daemon pod name"`
	Namespace string `json:"namespace,omitempty" jsonschema:"description=Target daemon pod namespace (default: kmesh-system)"`
}

type ConfigDumpRequest struct {
	PodName   string `json:"podName,omitempty" jsonschema:"description=Target daemon pod name (auto-discovered if empty)"`
	Namespace string `json:"namespace,omitempty" jsonschema:"description=Target daemon pod namespace (default: kmesh-system)"`
	Mode      string `json:"mode,omitempty" jsonschema:"description=Operating mode (kernel-native or dual-engine)"`
	Summary   bool   `json:"summary,omitempty" jsonschema:"description=Return counts and compact identities instead of the full dump (default: true)"`
	Filter    string `json:"filter,omitempty" jsonschema:"description=Case-insensitive substring matched against resource name/IP/UID"`
}

type ListWaypointsRequest struct {
	Namespace     string `json:"namespace,omitempty" jsonschema:"description=Target namespace"`
	AllNamespaces bool   `json:"allNamespaces,omitempty" jsonschema:"description=List across all namespaces"`
}

type GetWaypointStatusRequest struct {
	Name      string `json:"name" jsonschema:"description=Name of the waypoint gateway,required"`
	Namespace string `json:"namespace,omitempty" jsonschema:"description=Namespace of the waypoint"`
}

type GetAuthzStatusRequest struct {
	PodName   string `json:"podName,omitempty" jsonschema:"description=Target daemon pod name"`
	Namespace string `json:"namespace,omitempty" jsonschema:"description=Target daemon pod namespace (default: kmesh-system)"`
}

type GetDaemonHealthRequest struct {
	PodName   string `json:"podName,omitempty" jsonschema:"description=Target daemon pod name"`
	Namespace string `json:"namespace,omitempty" jsonschema:"description=Target daemon pod namespace (default: kmesh-system)"`
}

type GetLoggerLevelsRequest struct {
	PodName    string `json:"podName,omitempty" jsonschema:"description=Target daemon pod name"`
	Namespace  string `json:"namespace,omitempty" jsonschema:"description=Target daemon pod namespace (default: kmesh-system)"`
	LoggerName string `json:"loggerName,omitempty" jsonschema:"description=Optional specific logger module name"`
}

type ListDaemonPodsRequest struct {
	Namespace string `json:"namespace,omitempty" jsonschema:"description=Namespace where Kmesh is running (default: kmesh-system)"`
}

type GetMeshNamespacesRequest struct {
}
