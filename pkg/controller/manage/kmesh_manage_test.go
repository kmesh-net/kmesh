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

package kmeshmanage

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
	"k8s.io/client-go/tools/cache"

	"kmesh.net/kmesh/pkg/constants"
)

func waitAndCheckManageAction(t *testing.T, wg *sync.WaitGroup, mu *sync.Mutex, enabled *bool, disabled *bool, enableExpected bool, disableExpected bool) {
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, enableExpected, *enabled, "unexpected value for enabled flag")
	assert.Equal(t, disableExpected, *disabled, "unexpected value for disabled flag")
}

func TestPodWithLabelChangeTriggersManageAction(t *testing.T) {
	client := fake.NewSimpleClientset()

	err := os.Setenv("NODE_NAME", "test_node")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	controller, err := NewKmeshManageController(client)
	if err != nil {
		t.Fatalf("error creating KmeshManageController: %v", err)
	}

	stopChan := make(chan struct{})
	defer close(stopChan)

	controller.Run()
	cache.WaitForCacheSync(stopChan, controller.podInformer.HasSynced)

	var mu sync.Mutex
	enabled := false
	disabled := false

	// Create a WaitGroup to synchronize the test
	var wg sync.WaitGroup

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	patches.ApplyFunc(handleKmeshManage, func(ns string, op bool) error {
		mu.Lock()
		defer mu.Unlock()
		if op {
			enabled = true
		} else {
			disabled = true
		}
		// Signal that handleKmeshManage has been called
		wg.Done()
		return nil
	})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}

	wg.Add(1)
	_, err = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	waitAndCheckManageAction(t, &wg, &mu, &enabled, &disabled, true, false)

	enabled = false
	disabled = false

	delete(pod.Labels, constants.DataPlaneModeLabel)
	wg.Add(1)
	_, err = client.CoreV1().Pods("default").Update(context.TODO(), pod, metav1.UpdateOptions{})
	assert.NoError(t, err)

	waitAndCheckManageAction(t, &wg, &mu, &enabled, &disabled, false, true)
}

func TestPodWithoutLabelTriggersManageAction(t *testing.T) {
	client := fake.NewSimpleClientset()

	err := os.Setenv("NODE_NAME", "test_node")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	controller, err := NewKmeshManageController(client)
	if err != nil {
		t.Fatalf("error creating KmeshManageController: %v", err)
	}

	stopChan := make(chan struct{})
	defer close(stopChan)

	controller.Run()
	cache.WaitForCacheSync(stopChan, controller.podInformer.HasSynced)

	var mu sync.Mutex
	enabled := false
	disabled := false

	// Create a WaitGroup to synchronize the test
	var wg sync.WaitGroup

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	patches.ApplyFunc(handleKmeshManage, func(ns string, op bool) error {
		mu.Lock()
		defer mu.Unlock()
		if op {
			enabled = true
		} else {
			disabled = true
		}
		// Signal that handleKmeshManage has been called
		wg.Done()
		return nil
	})

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
			Labels:    map[string]string{},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}

	_, err = client.CoreV1().Pods("default").Create(context.TODO(), pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	enabled = false
	disabled = false

	pod.Labels[constants.DataPlaneModeLabel] = constants.DataPlaneModeKmesh
	wg.Add(1)
	_, err = client.CoreV1().Pods("default").Update(context.TODO(), pod, metav1.UpdateOptions{})
	assert.NoError(t, err)

	waitAndCheckManageAction(t, &wg, &mu, &enabled, &disabled, true, false)
}
