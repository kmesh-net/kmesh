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
	"context"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kmesh.net/kmesh/pkg/kube"
)

type mockCLIClient struct {
	kube.CLIClient
	pods *v1.PodList
	err  error
}

func (m *mockCLIClient) PodsForSelector(ctx context.Context, namespace string, labelSelectors ...string) (*v1.PodList, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.pods, nil
}

func TestGetKmeshDaemonPods(t *testing.T) {
	mockPods := &v1.PodList{
		Items: []v1.Pod{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kmesh-daemon-1",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name: "kmesh-daemon-2",
				},
			},
		},
	}

	cli := &mockCLIClient{pods: mockPods}
	pods, err := GetKmeshDaemonPods(cli)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(pods) != 2 || pods[0] != "kmesh-daemon-1" || pods[1] != "kmesh-daemon-2" {
		t.Errorf("expected [kmesh-daemon-1, kmesh-daemon-2], got %v", pods)
	}
}
