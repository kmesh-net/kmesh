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

package constants

import "testing"

func TestAdminPaths(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  string
		want string
	}{
		{"version", AdminPathVersion, "/version"},
		{"ready probe", AdminPathReadyProbe, "/debug/ready"},
		{"loggers", AdminPathLoggers, "/debug/loggers"},
		{"authz", AdminPathAuthz, "/authz"},
		{"config dump prefix", AdminPathConfigDumpPrefix, "/debug/config_dump"},
		{"config dump kernel-native", AdminPathConfigDumpAds, "/debug/config_dump/kernel-native"},
		{"config dump dual-engine", AdminPathConfigDumpWorkload, "/debug/config_dump/dual-engine"},
		{"bpf maps kernel-native", AdminPathBpfAdsMaps, "/debug/config_dump/bpf/kernel-native"},
		{"bpf maps dual-engine", AdminPathBpfWorkloadMaps, "/debug/config_dump/bpf/dual-engine"},
		{"accesslog", AdminPathAccesslog, "/accesslog"},
		{"monitoring", AdminPathMonitoring, "/monitoring"},
		{"workload metrics", AdminPathWorkloadMetrics, "/workload_metrics"},
		{"connection metrics", AdminPathConnectionMetrics, "/connection_metrics"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s path = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}
