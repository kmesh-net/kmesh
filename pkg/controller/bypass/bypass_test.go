package bypass

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
	"k8s.io/client-go/kubernetes/fake"
)

func waitAndCheckByPassAction(t *testing.T, wg *sync.WaitGroup, done chan struct{}, mu *sync.Mutex, enabled *bool, disabled *bool, enableExpected bool, disableExpected bool) {
	select {
	case <-done:
		mu.Lock()
		assert.Equal(t, enableExpected, *enabled, "unexpected value for enabled flag")
		assert.Equal(t, disableExpected, *disabled, "unexpected value for disabled flag")
		mu.Unlock()
	case <-time.After(1 * time.Second):
		t.Fatalf("timed out waiting for handleKmeshByPass to be called")
	}
}

func TestPodKmeshLabelChangeTriggersByPassAction(t *testing.T) {
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

	stopChan := make(chan struct{})
	defer close(stopChan)

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

	done := make(chan struct{})
	wg.Wait()
	close(done)

	waitAndCheckByPassAction(t, &wg, done, &mu, &enabled, &disabled, true, false)
}

func TestPodSidecarLabelChangeTriggersByPassAction(t *testing.T) {
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

	stopChan := make(chan struct{})
	defer close(stopChan)

	var mu sync.Mutex
	enabled := false
	disabled := false

	var wg sync.WaitGroup

	patches := gomonkey.NewPatches()
	defer patches.Reset()

	patches.ApplyFunc(addIptables, func(ns string) error {
		mu.Lock()
		defer mu.Unlock()
		enabled = true
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

	done := make(chan struct{})
	wg.Wait()
	close(done)

	waitAndCheckByPassAction(t, &wg, done, &mu, &enabled, &disabled, true, false)
}
