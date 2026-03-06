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

package bypass

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"istio.io/api/annotation"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	ns "kmesh.net/kmesh/pkg/controller/netns"
)

func TestBypassController(t *testing.T) {
	nodeName := "test_node"
	err := os.Setenv("NODE_NAME", nodeName)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	stopCh := make(chan struct{})
	defer close(stopCh)
	namespaceName := "default"
	namespace := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
			Labels: map[string]string{
				"istio-injection": "enabled",
			},
		},
	}
	client := fake.NewSimpleClientset(namespace)
	c := NewByPassController(client)
	c.Run(stopCh)

	enabled := atomic.Bool{}
	disabled := atomic.Bool{}

	var wg sync.WaitGroup

	patches1 := gomonkey.NewPatches()
	defer patches1.Reset()

	patches1.ApplyFunc(addIptables, func(ns string) error {
		enabled.Store(true)
		// Signal that addIptables has been called
		wg.Done()
		return nil
	})
	patches1.ApplyFunc(deleteIptables, func(ns string) error {
		disabled.Store(true)
		// Signal that addIptables has been called
		wg.Done()
		return nil
	})

	podWithBypassButNoSidecar := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-no-sidecar",
			Namespace: namespaceName,
			Labels: map[string]string{
				ByPassLabel: ByPassValue,
			},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
	}

	// case 1: pod with bypass label but no sidecar
	_, err = client.CoreV1().Pods(namespaceName).Create(context.TODO(), podWithBypassButNoSidecar, metav1.CreateOptions{})
	assert.NoError(t, err)
	assert.Equal(t, false, enabled.Load(), "unexpected value for enabled flag")
	assert.Equal(t, false, disabled.Load(), "unexpected value for disabled flag")

	podWithBypass := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: namespaceName,
			Labels: map[string]string{
				ByPassLabel: ByPassValue,
			},
			Annotations: map[string]string{
				annotation.SidecarStatus.Name: "placeholder",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
	}

	// case 2: pod with bypass label and sidecar
	wg.Add(1)
	_, err = client.CoreV1().Pods(namespaceName).Create(context.TODO(), podWithBypass, metav1.CreateOptions{})
	assert.NoError(t, err)
	wg.Wait()
	assert.Equal(t, true, enabled.Load(), "unexpected value for enabled flag")
	assert.Equal(t, false, disabled.Load(), "unexpected value for disabled flag")

	enabled.Store(false)
	disabled.Store(false)

	// case 3: pod update by removing bypass label
	// Update pod by removing the bypass label
	newPod := podWithBypass.DeepCopy()
	delete(newPod.Labels, ByPassLabel)
	wg.Add(1)
	_, err = client.CoreV1().Pods(namespaceName).Update(context.TODO(), newPod, metav1.UpdateOptions{})
	assert.NoError(t, err)
	wg.Wait()
	assert.Equal(t, false, enabled.Load(), "unexpected value for enabled flag")
	assert.Equal(t, true, disabled.Load(), "unexpected value for disabled flag")

	enabled.Store(false)
	disabled.Store(false)
	// case 4: Update pod by adding the bypass label
	newPod = podWithBypass.DeepCopy()
	newPod.Labels[ByPassLabel] = ByPassValue
	wg.Add(1)
	_, err = client.CoreV1().Pods(namespaceName).Update(context.TODO(), newPod, metav1.UpdateOptions{})
	assert.NoError(t, err)
	wg.Wait()
	assert.Equal(t, true, enabled.Load(), "unexpected value for enabled flag")
	assert.Equal(t, false, disabled.Load(), "unexpected value for disabled flag")
}

// TestBypassControllerKmeshRestart verifies the fix for the stale-rule cleanup
// on Kmesh daemon restart.
//
// Scenario:
//  1. A pod exists in the cluster with a sidecar but WITHOUT the bypass label.
//     (This models a pod whose bypass label was removed while the previous Kmesh
//     instance was running — or a pod that was never bypassed.)
//  2. A new ByPassController is created (simulating Kmesh restarting).
//  3. On startup the informer re-lists all pods and fires AddFunc for each.
//  4. The fix must call deleteIptables for such pods, cleaning up any stale rules.
func TestBypassControllerKmeshRestart(t *testing.T) {
	nodeName := "test_node"
	err := os.Setenv("NODE_NAME", nodeName)
	assert.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})

	namespaceName := "default"
	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: namespaceName,
			Labels: map[string]string{
				"istio-injection": "enabled",
			},
		},
	}

	// Pod has a sidecar but NO bypass label — simulates state after label removal.
	podWithSidecarNoBypass := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-restart",
			Namespace: namespaceName,
			// Deliberately omit the bypass label.
			Annotations: map[string]string{
				annotation.SidecarStatus.Name: "placeholder",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: nodeName,
		},
	}

	// Pre-populate the fake client with the pod so it exists before the
	// controller starts (i.e., simulate the "cluster state before restart").
	client := fake.NewSimpleClientset(namespace, podWithSidecarNoBypass)

	done := make(chan struct{})
	cleaned := atomic.Bool{}

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	// GetPodNSpath resolves the pod's network namespace from the host filesystem,
	// which doesn't exist in a unit-test environment. Patch it to return a
	// deterministic dummy path so execution reaches deleteIptables.
	patches.ApplyFunc(ns.GetPodNSpath, func(_ *corev1.Pod) (string, error) {
		return "/proc/1/ns/net", nil
	})
	patches.ApplyFunc(addIptables, func(_ string) error {
		// Should NOT be called for a pod without the bypass label.
		t.Errorf("addIptables unexpectedly called for pod without bypass label")
		return nil
	})
	patches.ApplyFunc(deleteIptables, func(_ string) error {
		cleaned.Store(true)
		close(done) // signal that cleanup was invoked
		return nil
	})

	stopCh := make(chan struct{})
	defer close(stopCh)

	c := NewByPassController(client)
	c.Run(stopCh)

	// Wait with a 2-second timeout so the test never hangs.
	select {
	case <-done:
		// cleanup fired as expected
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for deleteIptables to be called on Kmesh restart")
	}

	assert.True(t, cleaned.Load(), "expected deleteIptables to be called for pod without bypass label on Kmesh restart")
}
