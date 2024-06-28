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
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"kmesh.net/kmesh/pkg/constants"
)

func TestPodWithLabelAdditionTriggersManage(t *testing.T) {
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

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		mu.Lock()
		assert.True(t, enabled, "expected handleKmeshManage to be called for enabling Kmesh manage")
		assert.False(t, disabled, "expected handleKmeshManage not to be called for disabling Kmesh manage")
		mu.Unlock()
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for handleKmeshManage to be called")
	}

	podLister := controller.informerFactory.Core().V1().Pods().Lister()
	pods, err := podLister.Pods(pod.Namespace).List(labels.Everything())
	assert.NoError(t, err)
	assert.Equal(t, 1, len(pods), "expected One Pod in the lister after addition")

	// Reset variables
	mu.Lock()
	enabled = false
	disabled = false
	mu.Unlock()

	wg.Add(1)
	err = client.CoreV1().Pods("default").Delete(context.TODO(), "test-pod", metav1.DeleteOptions{})
	assert.NoError(t, err)

	done = make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		mu.Lock()
		assert.False(t, enabled, "expected handleKmeshManage not to be called for enabling Kmesh manage")
		assert.True(t, disabled, "expected handleKmeshManage to be called for disabling Kmesh manage")
		mu.Unlock()
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for handleKmeshManage to be called")
	}

	podLister = controller.informerFactory.Core().V1().Pods().Lister()
	pods, err = podLister.Pods(pod.Namespace).List(labels.Everything())
	assert.NoError(t, err)
	assert.Equal(t, 0, len(pods), "expected zero Pod in the lister after deletion")
}
