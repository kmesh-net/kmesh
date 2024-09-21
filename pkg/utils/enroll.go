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
	"strings"

	netns "github.com/containernetworking/plugins/pkg/ns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils/istio"
)

// ShouldEnroll checks whether a pod should be managed by kmesh.
// Kmesh manages a pod if a pod has "istio.io/dataplane-mode: kmesh" label
// or the namespace where it resides has the label while pod have no "istio.io/dataplane-mode: none" label
// Excluding cases: a pod has sidecar injected, or the pod is istio managed waypoint
// https://github.com/istio/istio/blob/33539491628fe5f3ad4f5f1fb339b0da9455c028/manifests/charts/istio-control/istio-discovery/files/waypoint.yaml#L35
func ShouldEnroll(pod *corev1.Pod, ns *corev1.Namespace) bool {
	if pod != nil {
		if istio.PodHasSidecar(pod) {
			return false
		}

		// exclude pod with host network set, otherwise it will cause other pods with host network to be managed by kmesh
		if pod.Spec.HostNetwork {
			return false
		}

		// If it is a Pod of waypoint, it should not be managed by Kmesh
		// Exclude istio managed gateway
		if gateway, ok := pod.Labels["gateway.istio.io/managed"]; ok {
			if strings.EqualFold(gateway, "istio.io-mesh-controller") {
				return false
			}
		}

		podMode := pod.Labels[constants.DataPlaneModeLabel]
		// Check if pod label contains istio.io/dataplane-mode: kmesh
		if strings.EqualFold(podMode, constants.DataPlaneModeKmesh) {
			return true
		}
	}

	// If namespace is not nil, check the namespace's label
	var nsMode string
	if ns != nil {
		nsMode = ns.Labels[constants.DataPlaneModeLabel]
	}

	// Check if ns label contains istio.io/dataplane-mode: kmesh, but pod is not excluded
	if strings.EqualFold(nsMode, constants.DataPlaneModeKmesh) && (pod == nil || pod.Labels[constants.DataPlaneModeLabel] != "none") {
		return true
	}
	return false
}

func HandleKmeshManage(ns string, enroll bool) error {
	execFunc := func(netns.NetNS) error {
		port := constants.OperEnableControl
		if !enroll {
			port = constants.OperDisableControl
		}
		return nets.TriggerControlCommand(port)
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		err = fmt.Errorf("enter ns path :%v, run execFunc failed: %v", ns, err)
		return err
	}
	return nil
}

var (
	annotationDelPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":null}}}`,
		constants.KmeshRedirectionAnnotation,
	))

	annotationAddPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":"%s"}}}`,
		constants.KmeshRedirectionAnnotation,
		"enabled",
	))
)

func PatchKmeshRedirectAnnotation(client kubernetes.Interface, pod *corev1.Pod) error {
	if pod.Annotations[constants.KmeshRedirectionAnnotation] == "enabled" {
		log.Debugf("Pod %s in namespace %s already has annotation %s", pod.Name, pod.Namespace, constants.KmeshRedirectionAnnotation)
		return nil
	}
	_, err := client.CoreV1().Pods(pod.Namespace).Patch(
		context.Background(),
		pod.Name,
		k8stypes.MergePatchType,
		annotationAddPatch,
		metav1.PatchOptions{},
	)
	return err
}

func DelKmeshRedirectAnnotation(client kubernetes.Interface, pod *corev1.Pod) error {
	if _, exists := pod.Annotations[constants.KmeshRedirectionAnnotation]; !exists {
		log.Debugf("Pod %s in namespace %s does not have annotation %s", pod.Name, pod.Namespace, constants.KmeshRedirectionAnnotation)
		return nil
	}
	_, err := client.CoreV1().Pods(pod.Namespace).Patch(
		context.Background(),
		pod.Name,
		k8stypes.MergePatchType,
		annotationDelPatch,
		metav1.PatchOptions{},
	)
	return err
}
