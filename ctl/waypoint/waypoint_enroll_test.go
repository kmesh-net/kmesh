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
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/utils"
)

// enrollTestClient implements kube.CLIClient with only Kube() wired to a fake
// clientset; namespaceIsEnrolledInKmesh only ever calls Kube().
type enrollTestClient struct{ k kubernetes.Interface }

func (c *enrollTestClient) Kube() kubernetes.Interface             { return c.k }
func (c *enrollTestClient) GatewayAPI() gatewayapiclient.Interface { return nil }
func (c *enrollTestClient) PodsForSelector(context.Context, string, ...string) (*corev1.PodList, error) {
	return nil, nil
}

func (c *enrollTestClient) NewPortForwarder(string, string, string, int, int) (kube.PortForwarder, error) {
	return nil, nil
}

// TestNamespaceIsEnrolledInKmesh checks that kmeshctl agrees with the daemon
// about which istio.io/dataplane-mode values enroll a namespace. The daemon
// (pkg/utils.ShouldEnroll) compares the value case-insensitively, so kmeshctl
// must do the same instead of only accepting the exact string "Kmesh".
func TestNamespaceIsEnrolledInKmesh(t *testing.T) {
	cases := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{name: "exact Kmesh", labels: map[string]string{constants.DataPlaneModeLabel: "Kmesh"}, want: true},
		{name: "lowercase kmesh", labels: map[string]string{constants.DataPlaneModeLabel: "kmesh"}, want: true},
		{name: "uppercase KMESH", labels: map[string]string{constants.DataPlaneModeLabel: "KMESH"}, want: true},
		{name: "other mode", labels: map[string]string{constants.DataPlaneModeLabel: "ambient"}, want: false},
		{name: "empty value", labels: map[string]string{constants.DataPlaneModeLabel: ""}, want: false},
		{name: "no labels", labels: nil, want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "test-ns", Labels: tc.labels}}
			cli := &enrollTestClient{k: fake.NewSimpleClientset(ns)}

			got, err := namespaceIsEnrolledInKmesh(context.Background(), cli, "test-ns")
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("namespaceIsEnrolledInKmesh(labels=%v) = %v, want %v", tc.labels, got, tc.want)
			}

			// The daemon's decision for the same namespace must match.
			if daemon := utils.ShouldEnroll(nil, ns); daemon != tc.want {
				t.Fatalf("utils.ShouldEnroll(labels=%v) = %v, want %v; kmeshctl and daemon disagree", tc.labels, daemon, tc.want)
			}
		})
	}
}

func TestNamespaceIsEnrolledInKmesh_MissingNamespace(t *testing.T) {
	cli := &enrollTestClient{k: fake.NewSimpleClientset()}
	if _, err := namespaceIsEnrolledInKmesh(context.Background(), cli, "missing"); err == nil {
		t.Fatalf("expected an error for a missing namespace")
	}
}
