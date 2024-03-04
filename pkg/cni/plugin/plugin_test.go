/*
 * Copyright 2023 The Kmesh Authors.
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
 *
 * Author: bitcoffee
 * Create: 2023-11-19
 */

package plugin

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
)

func Test_checkKmesh(t *testing.T) {
	type args struct {
		client kubernetes.Interface
		pod    *corev1.Pod
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "test1: namespace with istio-injection=enabled, pod with sidecar inject annotation, should return false",
			args: args{
				client: fake.NewSimpleClientset(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "utNs",
						Labels: map[string]string{
							"istio-injection": "ebable",
						},
					},
				}),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "utPod",
						Namespace: "utNs",
						Annotations: map[string]string{
							"sidecar.istio.io/inject": "true",
						},
					},
				},
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkKmesh(tt.args.client, tt.args.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkKmesh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("checkKmesh() = %v, want %v", got, tt.want)
			}
		})
	}
}
