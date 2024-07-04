/*
 * Copyright 2024 The Kmesh Authors.
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
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestPodKmeshLabelChangeTriggersByPassKmeshAction(t *testing.T) {
	client := fake.NewSimpleClientset()

	err := os.Setenv("NODE_NAME", "test_node")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	err = StartByPassController(client)
	if err != nil {
		t.Fatalf("error creating ByPassController: %v", err)
	}

	var mu sync.Mutex
	enabled := false
	disabled := false

	var wg sync.WaitGroup

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	patches.ApplyFunc(handleKmeshBypass, func(ns string, op int) error {
		mu.Lock()
		defer mu.Unlock()
		if op == 1 {
			enabled = true
		} else {
			disabled = true
		}
		// Signal that handleKmeshBypass has been called
		wg.Done()
		return nil
	})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels: map[string]string{
				"kmesh.net/bypass": "enabled",
			},
			Annotations: map[string]string{
				"kmesh.net/redirection": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}

	wg.Add(1)
	_, err = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	wg.Wait()
	assert.Equal(t, true, enabled, "unexpected value for enabled flag")
	assert.Equal(t, false, disabled, "unexpected value for disabled flag")

	enabled = false
	disabled = false

	delete(pod.Labels, "kmesh.net/bypass")
	wg.Add(1)
	_, err = client.CoreV1().Pods("default").Update(context.TODO(), pod, metav1.UpdateOptions{})
	assert.NoError(t, err)

	wg.Wait()
	assert.Equal(t, true, disabled, "unexpected value for enabled flag")
}

func TestPodSidecarLabelChangeTriggersAddIptablesAction(t *testing.T) {
	client := fake.NewSimpleClientset()

	err := os.Setenv("NODE_NAME", "test_node")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	err = StartByPassController(client)
	if err != nil {
		t.Fatalf("error creating ByPassController: %v", err)
	}

	var mu sync.Mutex
	enabled := false
	disabled := false

	var wg sync.WaitGroup

	patches1 := gomonkey.NewPatches()
	defer patches1.Reset()

	patches1.ApplyFunc(addIptables, func(ns string) error {
		mu.Lock()
		defer mu.Unlock()
		enabled = true
		// Signal that addIptables has been called
		wg.Done()
		return nil
	})

	patches2 := gomonkey.NewPatches()
	defer patches2.Reset()

	patches2.ApplyFunc(deleteIptables, func(ns string) error {
		mu.Lock()
		defer mu.Unlock()
		disabled = true
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

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: namespaceName,
			Labels: map[string]string{
				"kmesh.net/bypass": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}

	wg.Add(1)
	_, err = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	wg.Wait()
	assert.Equal(t, true, enabled, "unexpected value for enabled flag")

	enabled = false
	disabled = false

	delete(pod.Labels, "kmesh.net/bypass")
	wg.Add(1)
	_, err = client.CoreV1().Pods("default").Update(context.TODO(), pod, metav1.UpdateOptions{})
	assert.NoError(t, err)

	wg.Wait()
	assert.Equal(t, true, disabled, "unexpected value for enabled flag")
}
