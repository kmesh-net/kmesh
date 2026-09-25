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

	"kmesh.net/kmesh/pkg/kube"
)

// fakeCLIClient implements kube.CLIClient with only Kube() wired to a fake
// clientset; namespaceHasLabel only ever calls Kube(), so the rest are stubs.
type fakeCLIClient struct{ k kubernetes.Interface }

func (f *fakeCLIClient) Kube() kubernetes.Interface             { return f.k }
func (f *fakeCLIClient) GatewayAPI() gatewayapiclient.Interface { return nil }
func (f *fakeCLIClient) PodsForSelector(context.Context, string, ...string) (*corev1.PodList, error) {
	return nil, nil
}
func (f *fakeCLIClient) NewPortForwarder(string, string, string, int, int) (kube.PortForwarder, error) {
	return nil, nil
}

// TestNamespaceHasLabel_EmptyValueIsStillPresent verifies that a label present
// with an empty value counts as present. In Kubernetes an empty-valued label
// (e.g. istio.io/use-waypoint: "") is a valid, present label, so a presence
// check must not treat it as absent. namespaceHasLabel used `Labels[l] != ""`,
// which wrongly reported such a namespace as unlabeled and let the
// waypoint-apply overwrite guard be skipped.
func TestNamespaceHasLabel_EmptyValueIsStillPresent(t *testing.T) {
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "test-ns",
			Labels: map[string]string{KmeshUseWaypointLabel: ""},
		},
	}
	cli := &fakeCLIClient{k: fake.NewSimpleClientset(ns)}

	has, err := namespaceHasLabel(cli, "test-ns", KmeshUseWaypointLabel)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !has {
		t.Fatalf("namespaceHasLabel returned false for a namespace that has %q set to an empty value; an empty-valued label is present, not absent", KmeshUseWaypointLabel)
	}
}
