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

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"istio.io/api/annotation"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPodSidecarLabelChangeTriggersAddIptablesAction(t *testing.T) {
	client := fake.NewSimpleClientset()

	err := os.Setenv("NODE_NAME", "test_node")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	stopCh := make(<-chan struct{})
	c := NewByPassController(client)
	go c.Run(stopCh)
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

	patches2 := gomonkey.NewPatches()
	defer patches2.Reset()

	patches2.ApplyFunc(deleteIptables, func(ns string) error {
		disabled.Store(true)
		// Signal that addIptables has been called
		wg.Done()
		return nil
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
	_, err = client.CoreV1().Namespaces().Create(context.TODO(), namespace, metav1.CreateOptions{})
	require.NoError(t, err)

	podWithBypassButNoSidecar := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod-no-sidecar",
			Namespace: namespaceName,
			Labels: map[string]string{
				ByPassLabel: ByPassValue,
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}

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
			NodeName: "test-node",
		},
	}

	wg.Add(1)
	_, err = client.CoreV1().Pods(namespaceName).Create(context.TODO(), podWithBypass, metav1.CreateOptions{})
	assert.NoError(t, err)
	wg.Wait()
	assert.Equal(t, true, enabled.Load(), "unexpected value for enabled flag")
	assert.Equal(t, false, disabled.Load(), "unexpected value for disabled flag")

	enabled.Store(false)
	disabled.Store(false)

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
	// Update pod by adding the bypass label
	newPod = podWithBypass.DeepCopy()
	newPod.Labels[ByPassLabel] = ByPassValue
	wg.Add(1)
	_, err = client.CoreV1().Pods(namespaceName).Update(context.TODO(), newPod, metav1.UpdateOptions{})
	assert.NoError(t, err)
	wg.Wait()
	assert.Equal(t, true, enabled.Load(), "unexpected value for enabled flag")
	assert.Equal(t, false, disabled.Load(), "unexpected value for disabled flag")
}
