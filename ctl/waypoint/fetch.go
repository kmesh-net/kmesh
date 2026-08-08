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
	"cmp"
	"context"
	"fmt"
	"slices"

	"istio.io/api/label"
	"istio.io/istio/pilot/pkg/model/kstatus"
	"istio.io/istio/pkg/config/constants"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gateway "sigs.k8s.io/gateway-api/apis/v1"

	"kmesh.net/kmesh/pkg/kube"
)

// WaypointInfo is a structured summary of a managed waypoint Gateway.
type WaypointInfo struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Revision  string `json:"revision"`
	Programmed string `json:"programmed"`
}

// WaypointConditionStatus is a structured waypoint status row.
type WaypointConditionStatus struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	Type      string `json:"type"`
	Reason    string `json:"reason"`
	Message   string `json:"message"`
}

// ListWaypoints lists Gateways with the istio-waypoint GatewayClass.
// If namespace is empty, all namespaces are listed.
func ListWaypoints(kubeClient kube.CLIClient, namespace string) ([]WaypointInfo, error) {
	gws, err := kubeClient.GatewayAPI().GatewayV1().Gateways(namespace).
		List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	filtered := make([]gateway.Gateway, 0, len(gws.Items))
	for _, gw := range gws.Items {
		if gw.Spec.GatewayClassName != constants.WaypointGatewayClassName {
			continue
		}
		filtered = append(filtered, gw)
	}
	slices.SortFunc(filtered, func(i, j gateway.Gateway) int {
		if r := cmp.Compare(i.Namespace, j.Namespace); r != 0 {
			return r
		}
		return cmp.Compare(i.Name, j.Name)
	})

	out := make([]WaypointInfo, 0, len(filtered))
	for _, gw := range filtered {
		programmed := kstatus.StatusFalse
		rev := gw.Labels[label.IoIstioRev.Name]
		if rev == "" {
			rev = "default"
		}
		for _, cond := range gw.Status.Conditions {
			if cond.Type == string(gateway.GatewayConditionProgrammed) {
				programmed = string(cond.Status)
			}
		}
		out = append(out, WaypointInfo{
			Namespace: gw.Namespace,
			Name:      gw.Name,
			Revision:  rev,
			Programmed: programmed,
		})
	}
	return out, nil
}

// GetWaypointStatuses returns the Programmed condition snapshot for waypoints in a namespace.
// Unlike the CLI status command, this does not poll/wait.
func GetWaypointStatuses(kubeClient kube.CLIClient, namespace string) ([]WaypointConditionStatus, error) {
	ns := namespaceOrDefault(namespace)
	waypoints, err := ListWaypoints(kubeClient, ns)
	if err != nil {
		return nil, err
	}

	out := make([]WaypointConditionStatus, 0, len(waypoints))
	for _, wp := range waypoints {
		gwc, err := kubeClient.GatewayAPI().GatewayV1().Gateways(wp.Namespace).Get(context.TODO(), wp.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get waypoint %s/%s: %w", wp.Namespace, wp.Name, err)
		}
		var cond metav1.Condition
		for _, c := range gwc.Status.Conditions {
			if c.Type == string(gateway.GatewayConditionProgrammed) {
				cond = c
				break
			}
		}
		out = append(out, WaypointConditionStatus{
			Namespace: gwc.Namespace,
			Name:      gwc.Name,
			Status:    string(cond.Status),
			Type:      cond.Type,
			Reason:    cond.Reason,
			Message:   cond.Message,
		})
	}
	return out, nil
}
