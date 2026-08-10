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
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/kube"
)

// ListDaemonPods lists kmesh-daemon pods (app=kmesh) in the given namespace.
// If namespace is empty, KmeshNamespace is used.
func ListDaemonPods(ctx context.Context, cli kube.CLIClient, namespace string) (*corev1.PodList, error) {
	if namespace == "" {
		namespace = KmeshNamespace
	}
	podList, err := cli.PodsForSelector(ctx, namespace, KmeshLabel)
	if err != nil {
		return nil, fmt.Errorf("failed to list kmesh daemon pods in %s: %w", namespace, err)
	}
	return podList, nil
}

// ListMeshNamespaces returns namespaces labeled with istio.io/dataplane-mode=kmesh.
func ListMeshNamespaces(ctx context.Context, cli kube.CLIClient) ([]string, error) {
	nsList, err := cli.Kube().CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", constants.DataPlaneModeLabel, constants.DataPlaneModeKmesh),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list mesh namespaces: %w", err)
	}
	names := make([]string, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		names = append(names, ns.Name)
	}
	return names, nil
}
