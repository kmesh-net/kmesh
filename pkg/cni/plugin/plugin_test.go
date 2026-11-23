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

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/containernetworking/cni/pkg/skel"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/rest"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/utils"
)

func buildStdinData(t *testing.T, mode string, enableIPSec bool) []byte {
	t.Helper()
	stdin := map[string]interface{}{
		"cniVersion":  "1.1.0",
		"name":        "kmesh-cni-test",
		"type":        "kmesh-cni",
		"mode":        mode,
		"enableIpSec": enableIPSec,
		"prevResult": map[string]interface{}{
			"cniVersion": "1.1.0",
			"interfaces": []map[string]interface{}{{"name": "eth0"}},
			"ips":        []map[string]interface{}{{"address": "10.1.1.2/24", "interface": 0}},
		},
	}
	b, err := json.Marshal(stdin)
	require.NoError(t, err)
	return b
}

func isAnnotated(t *testing.T, client kubernetes.Interface, namespace, name string) bool {
	t.Helper()
	got, err := client.CoreV1().Pods(namespace).Get(context.TODO(), name, metav1.GetOptions{})
	require.NoError(t, err)
	return utils.AnnotationEnabled(got.Annotations[constants.KmeshRedirectionAnnotation])
}

// TestCmdAddAnnotatesOnlyAfterAttachSucceeds covers the fix for
// https://github.com/kmesh-net/kmesh/issues/1856: CmdAdd must not patch the
// kmesh-managed annotation until every dataplane attach step it performs
// (XDP auth in dual-engine mode, TC IPsec marking when enabled) has actually
// succeeded. It exercises the real CmdAdd/PatchKmeshRedirectAnnotation code
// path against a fake clientset, patching only the netns/netlink boundary
// (kube.CreateKubeClient, netns.WithNetNSPath, enableXdpAuth,
// enableTcMarkEncrypt) since those require a real network namespace.
func TestCmdAddAnnotatesOnlyAfterAttachSucceeds(t *testing.T) {
	const (
		podName      = "test-pod"
		podNamespace = "default"
	)

	newPodAndNamespace := func(t *testing.T) kubernetes.Interface {
		t.Helper()
		client := fake.NewSimpleClientset()
		_, err := client.CoreV1().Namespaces().Create(context.TODO(), &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{Name: podNamespace},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
		_, err = client.CoreV1().Pods(podNamespace).Create(context.TODO(), &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      podName,
				Namespace: podNamespace,
				Labels:    map[string]string{constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh},
			},
		}, metav1.CreateOptions{})
		require.NoError(t, err)
		return client
	}

	newArgs := func(t *testing.T, mode string, enableIPSec bool) *skel.CmdArgs {
		t.Helper()
		return &skel.CmdArgs{
			ContainerID: "test-container",
			Netns:       "/proc/1/ns/net",
			IfName:      "eth0",
			Args:        fmt.Sprintf("IgnoreUnknown=1;K8S_POD_NAMESPACE=%s;K8S_POD_NAME=%s", podNamespace, podName),
			StdinData:   buildStdinData(t, mode, enableIPSec),
		}
	}

	applyCommonPatches := func(patches *gomonkey.Patches, client kubernetes.Interface) {
		patches.ApplyFunc(kube.CreateKubeClient, func(string, ...func(c *rest.Config)) (kubernetes.Interface, error) {
			return client, nil
		})
		patches.ApplyFunc(utils.HandleKmeshManage, func(string, bool) error { return nil })
		patches.ApplyFunc(netns.WithNetNSPath, func(_ string, toRun func(netns.NetNS) error) error {
			return toRun(nil)
		})
	}

	t.Run("xdp attach failure leaves the pod unannotated", func(t *testing.T) {
		client := newPodAndNamespace(t)
		patches := gomonkey.NewPatches()
		defer patches.Reset()
		applyCommonPatches(patches, client)
		patches.ApplyFunc(enableXdpAuth, func(string) error {
			return fmt.Errorf("injected xdp attach failure")
		})

		err := CmdAdd(newArgs(t, constants.DualEngineMode, false))
		assert.Error(t, err)
		assert.False(t, isAnnotated(t, client, podNamespace, podName),
			"pod must not be annotated as kmesh-managed when the xdp attach failed")
	})

	t.Run("tc ipsec attach failure leaves the pod unannotated", func(t *testing.T) {
		client := newPodAndNamespace(t)
		patches := gomonkey.NewPatches()
		defer patches.Reset()
		applyCommonPatches(patches, client)
		patches.ApplyFunc(enableTcMarkEncrypt, func(*skel.CmdArgs) error {
			return fmt.Errorf("injected tc ipsec attach failure")
		})

		err := CmdAdd(newArgs(t, constants.KernelNativeMode, true))
		assert.Error(t, err)
		assert.False(t, isAnnotated(t, client, podNamespace, podName),
			"pod must not be annotated as kmesh-managed when the tc ipsec attach failed")
	})

	t.Run("all attach steps succeeding annotates the pod", func(t *testing.T) {
		client := newPodAndNamespace(t)
		patches := gomonkey.NewPatches()
		defer patches.Reset()
		applyCommonPatches(patches, client)
		patches.ApplyFunc(enableXdpAuth, func(string) error { return nil })
		patches.ApplyFunc(enableTcMarkEncrypt, func(*skel.CmdArgs) error { return nil })

		err := CmdAdd(newArgs(t, constants.DualEngineMode, true))
		assert.NoError(t, err)
		assert.True(t, isAnnotated(t, client, podNamespace, podName),
			"pod must be annotated as kmesh-managed once every attach step succeeded")
	})
}
