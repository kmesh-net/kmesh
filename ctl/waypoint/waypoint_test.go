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

package waypoint

import (
	"bytes"
	"reflect"
	"testing"

	"istio.io/api/label"
	gateway "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/yaml"
)

func TestGenerateWaypointLabels(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantLabels map[string]string
	}{
		{
			name: "traffic type and revision",
			args: []string{"generate", "--for", "workload", "--revision", "canary"},
			wantLabels: map[string]string{
				KmeshWaypointForTrafficTypeLabel: "workload",
				label.IoIstioRev.Name:            "canary",
			},
		},
		{
			name: "traffic type only",
			args: []string{"generate", "--for", "workload"},
			wantLabels: map[string]string{
				KmeshWaypointForTrafficTypeLabel: "workload",
			},
		},
		{
			name: "revision only",
			args: []string{"generate", "--revision", "canary"},
			wantLabels: map[string]string{
				label.IoIstioRev.Name: "canary",
			},
		},
		{
			name: "no labels",
			args: []string{"generate"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := NewCmd()
			var output bytes.Buffer
			cmd.SetOut(&output)
			cmd.SetArgs(tt.args)

			if err := cmd.Execute(); err != nil {
				t.Fatalf("generate waypoint: %v", err)
			}

			var got gateway.Gateway
			if err := yaml.Unmarshal(output.Bytes(), &got); err != nil {
				t.Fatalf("unmarshal generated gateway: %v", err)
			}
			if !reflect.DeepEqual(got.Labels, tt.wantLabels) {
				t.Errorf("labels = %v, want %v", got.Labels, tt.wantLabels)
			}
		})
	}
}
