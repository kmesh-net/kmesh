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

package ipsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/cilium/ebpf"

	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/encryption"
	"kmesh.net/kmesh/pkg/kube"
	v1alpha1 "kmesh.net/kmesh/pkg/kube/apis/kmeshnodeinfo/v1alpha1"
	fakeKmeshClientset "kmesh.net/kmesh/pkg/kube/nodeinfo/clientset/versioned/fake"
	"kmesh.net/kmesh/pkg/utils"
	"kmesh.net/kmesh/pkg/utils/test"
)

var (
	testLocalNodeInfo = &v1alpha1.KmeshNodeInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-local-node",
			Namespace: "kmesh-system",
		},
		Spec: v1alpha1.KmeshNodeInfoSpec{
			SPI:       123,
			Addresses: []string{"10.0.0.1", "192.168.1.1"},
			BootID:    "test-boot-id",
			PodCIDRs:  []string{"10.244.0.1/24", "10.244.0.2/24"},
		},
	}

	testRemoteNodeInfo = &v1alpha1.KmeshNodeInfo{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-remote-node",
			Namespace: "kmesh-system",
		},
		Spec: v1alpha1.KmeshNodeInfoSpec{
			SPI:       456,
			Addresses: []string{"10.0.0.2"},
			BootID:    "test-boot-id-2",
			PodCIDRs:  []string{"10.244.1.1/24", "10.244.1.2/24"},
		},
	}

	testK8sNode = &corev1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-local-node",
		},
		Status: corev1.NodeStatus{
			Addresses: []corev1.NodeAddress{
				{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				{Type: corev1.NodeExternalIP, Address: "192.168.1.1"},
			},
			NodeInfo: corev1.NodeSystemInfo{
				BootID: "test-boot-id",
			},
		},
		Spec: corev1.NodeSpec{
			PodCIDRs: []string{"10.244.0.1/24", "10.244.0.2/24"},
		},
	}

	testKey = encryption.IpSecKey{
		Spi:         1,
		AeadKeyName: "rfc4106(gcm(aes))",
		AeadKey:     DecodeHex("abc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462161"),
		Length:      128,
	}
)

func prepareForController(t *testing.T) error {
	// Create temporary directory and file for testing
	tempDir := t.TempDir()
	tempFile := filepath.Join(tempDir, "kmesh-ipsec", "ipSec")
	err := os.MkdirAll(filepath.Dir(tempFile), 0755)
	if err != nil {
		return err
	}

	// Create a simple valid ipSec file content
	keyJson, err := json.Marshal(testKey)
	if err != nil {
		return err
	}

	err = os.WriteFile(tempFile, keyJson, 0644) // create ./kmesh-ipsec/ipSec
	if err != nil {
		return err
	}

	// change workdir to tmpdir to read ipsec key file, to avoid none file error
	oldDir, err := os.Getwd()
	if err != nil {
		return err
	}
	err = os.Chdir(tempDir)
	if err != nil {
		return err
	}

	old := os.Getenv("NODE_NAME")
	os.Setenv("NODE_NAME", "test-local-node")
	t.Cleanup(func() {
		os.Chdir(oldDir)
		os.Setenv("NODE_NAME", old)
	})
	return nil
}

func TestNewIPsecController(t *testing.T) {
	testCases := []struct {
		name          string
		setupEnv      func() func()
		expectedError bool
		errorContains string
	}{
		{
			name: "successful_creation",
			setupEnv: func() func() {
				return func() {
					err := prepareForController(t)
					assert.NoError(t, err)
				}
			},
			expectedError: false,
		},
		{
			name: "missing_node_name_env",
			setupEnv: func() func() {
				return func() {
					os.Setenv("NODE_NAME", "")
				}
			},
			expectedError: true,
			errorContains: "failed to get kmesh node info from k8s",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// Setup environment
			setupEnv := test.setupEnv()
			setupEnv()

			// Setup patches
			patches := gomonkey.NewPatches()
			defer patches.Reset()

			// Create fake clients
			k8sClient := fake.NewSimpleClientset(testK8sNode)
			kmeshClient := fakeKmeshClientset.NewSimpleClientset(testLocalNodeInfo)

			// Create mock eBPF components
			mockMap := &ebpf.Map{}
			mockProg := &ebpf.Program{}

			// Apply patches for kube.GetKmeshNodeInfoClient to return our fake client
			clientPatches := gomonkey.NewPatches()
			clientPatches.ApplyFuncReturn(kube.GetKmeshNodeInfoClient, kmeshClient, nil)
			defer clientPatches.Reset()

			controller, err := NewIPsecController(k8sClient, mockMap, mockProg)

			if test.expectedError {
				assert.Error(t, err)
				if test.errorContains != "" {
					assert.Contains(t, err.Error(), test.errorContains)
				}
				assert.Nil(t, controller)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, controller)
				assert.Equal(t, "test-local-node", controller.kmeshNodeInfo.Name)
			}
		})
	}
}

func TestHandleKNIEvents(t *testing.T) {
	err := prepareForController(t)
	require.NoError(t, err)
	// Setup patches
	patches := gomonkey.NewPatches()
	defer patches.Reset()

	// Create fake clients
	k8sClient := fake.NewSimpleClientset(testK8sNode)
	kmeshClient := fakeKmeshClientset.NewSimpleClientset()
	patches.ApplyFuncReturn(kube.GetKmeshNodeInfoClient, kmeshClient, nil)

	prepare := func(t *testing.T) *IPSecController {
		// Create mock eBPF components
		mockMap := &ebpf.Map{}
		mockProg := &ebpf.Program{}
		controller, err := NewIPsecController(k8sClient, mockMap, mockProg)
		assert.NoError(t, err)
		assert.NotNil(t, controller)
		return controller
	}

	t.Run("handleKNIAdd", func(t *testing.T) {
		controller := prepare(t)

		// Test adding a remote node (should be added to queue)
		controller.handleKNIAdd(testRemoteNodeInfo)
		assert.Eventually(t, func() bool { return controller.queue.Len() == 1 }, 100*time.Millisecond, 10*time.Millisecond)

		// Test adding local node (should be ignored)
		controller.queue = workqueue.NewTypedRateLimitingQueue(workqueue.DefaultTypedControllerRateLimiter[any]()) // Reset queue
		controller.handleKNIAdd(testLocalNodeInfo)
		assert.Eventually(t, func() bool { return controller.queue.Len() == 0 }, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("handleKNIUpdate", func(t *testing.T) {
		controller := prepare(t)

		// Test updating with same spec (should be ignored)
		controller.handleKNIUpdate(testRemoteNodeInfo, testRemoteNodeInfo)
		assert.Eventually(t, func() bool { return controller.queue.Len() == 0 }, 100*time.Millisecond, 10*time.Millisecond)

		// Test updating local node (should be ignored)
		controller.handleKNIUpdate(testLocalNodeInfo, testLocalNodeInfo)
		assert.Eventually(t, func() bool { return controller.queue.Len() == 0 }, 100*time.Millisecond, 10*time.Millisecond)

		// Test updating with different spec (should be added to queue)
		updatedNode := testRemoteNodeInfo.DeepCopy()
		updatedNode.Spec.SPI = 789
		controller.handleKNIUpdate(testRemoteNodeInfo, updatedNode)
		assert.Eventually(t, func() bool { return controller.queue.Len() == 1 }, 100*time.Millisecond, 10*time.Millisecond)
	})

	t.Run("handleKNIDelete", func(t *testing.T) {
		// Test case 1: Normal delete of remote node
		t.Run("Normal delete of remote node", func(t *testing.T) {
			controller := prepare(t)
			// Create patches for network namespace operations
			nsPatches := gomonkey.NewPatches()
			defer nsPatches.Reset()

			// Mock netns.WithNetNSPath to avoid actual network operations
			nsPatches.ApplyFunc(netns.WithNetNSPath, func(nspath string, toRun func(netns.NetNS) error) error {
				return toRun(nil) // Mock successful execution
			})

			// Mock ipsecHandler.Clean to track calls
			cleanCallCount := 0
			cleanPatches := gomonkey.NewPatches()
			defer cleanPatches.Reset()
			cleanPatches.ApplyMethod(controller.ipsecHandler, "Clean", func(_ *IpSecHandler, targetIP string) error {
				cleanCallCount++
				// Verify that the targetIP is one of the remote node's addresses
				assert.Contains(t, testRemoteNodeInfo.Spec.Addresses, targetIP)
				return nil
			})

			// Mock deleteKNIMapCIDR to track calls
			deleteMapCallCount := 0
			deleteMapPatches := gomonkey.NewPatches()
			defer deleteMapPatches.Reset()
			deleteMapPatches.ApplyPrivateMethod(reflect.TypeOf(controller), "deleteKNIMapCIDR", func(c *IPSecController, remoteCIDR string, mapfd *ebpf.Map) {
				deleteMapCallCount++
				// Verify that the remoteCIDR is one of the remote node's PodCIDRs
				assert.Contains(t, testRemoteNodeInfo.Spec.PodCIDRs, remoteCIDR)
			})

			// Call handleKNIDelete with remote node
			controller.handleKNIDelete(testRemoteNodeInfo)

			// Verify that Clean was called for each address
			assert.Equal(t, len(testRemoteNodeInfo.Spec.Addresses), cleanCallCount, "ipsecHandler.Clean should be called once for each address")
			// Verify that deleteKNIMapCIDR was called for each PodCIDR
			assert.Equal(t, len(testRemoteNodeInfo.Spec.PodCIDRs), deleteMapCallCount, "deleteKNIMapCIDR should be called once for each PodCIDR")
		})

		// Test case 2: WithNetNSPath error
		t.Run("network_namespace_error", func(t *testing.T) {
			controller := prepare(t)
			// Create patches for network namespace operations that fail
			nsPatches := gomonkey.NewPatches()
			defer nsPatches.Reset()

			nsPatches.ApplyFunc(netns.WithNetNSPath, func(nspath string, toRun func(netns.NetNS) error) error {
				return fmt.Errorf("network namespace error")
			})

			// Mock deleteKNIMapCIDR to track calls
			deleteMapCalled := false
			deleteMapPatches := gomonkey.NewPatches()
			defer deleteMapPatches.Reset()
			deleteMapPatches.ApplyPrivateMethod(reflect.TypeOf(controller), "deleteKNIMapCIDR", func(c *IPSecController, remoteCIDR string, mapfd *ebpf.Map) {
				deleteMapCalled = true
			})

			// Call handleKNIDelete - should not process map deletions when network operations fail
			controller.handleKNIDelete(testRemoteNodeInfo)

			// Verify that deleteKNIMapCIDR will not called when network namespace fail
			assert.False(t, deleteMapCalled, "deleteKNIMapCIDR should not be called if network operations fail")
		})
	})
}

func getLoader(t *testing.T) (*bpf.BpfLoader, test.CleanupFn) {
	config := options.BpfConfig{
		Mode:        constants.DualEngineMode,
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
		EnableIPsec: true,
	}
	cleanfn, loader := test.InitBpfMap(t, config)

	return loader, cleanfn
}

func TestMapOperations(t *testing.T) {
	loader, cleanfn := getLoader(t)
	t.Cleanup(cleanfn)
	kniMap := loader.GetBpfWorkload().Tc.KmeshTcMarkEncryptObjects.KmNodeinfo
	decryptProg := loader.GetBpfWorkload().Tc.KmeshTcMarkDecryptPrograms.TcMarkDecrypt

	err := prepareForController(t)
	require.NoError(t, err)
	// Setup patches
	patches := gomonkey.NewPatches()
	defer patches.Reset()

	// Create fake clients
	k8sClient := fake.NewSimpleClientset(testK8sNode)
	kmeshClient := fakeKmeshClientset.NewSimpleClientset()
	patches.ApplyFuncReturn(kube.GetKmeshNodeInfoClient, kmeshClient, nil)

	// Create controller
	controller, err := NewIPsecController(k8sClient, kniMap, decryptProg)
	require.NoError(t, err)
	require.NotNil(t, controller)

	// Test multiple address
	testCases := []struct {
		name     string
		cidr     string
		expected bool
	}{
		{"valid_ipv4_cidr", "192.168.1.0/24", true},
		{"valid_ipv4_cidr_32", "10.0.0.1/32", true},
		{"valid_ipv6_cidr", "2001:db8::/64", true},
		{"invalid_cidr", "not-a-cidr", false},
	}

	for _, tc := range testCases { // not use t.Run to avoid parallel execution issues
		// Add CIDR to KNI map
		err := controller.updateKNIMapCIDR(tc.cidr, kniMap)
		if tc.expected {
			require.NoError(t, err)

			// Verify add success
			key, err := controller.generalKNIMapKey(tc.cidr)
			require.NoError(t, err)
			var value uint32
			err = kniMap.Lookup(key, &value)
			require.NoError(t, err)
			assert.Equal(t, uint32(1), value)

			// Delete CIDR
			controller.deleteKNIMapCIDR(tc.cidr, kniMap)

			// Verify delete success
			err = kniMap.Lookup(key, &value)
			assert.Error(t, err) // not found
		} else {
			assert.Error(t, err)
		}
	}
}

// Test update local kmesh node info and sync all node info
func TestNodeOperations(t *testing.T) {
	err := prepareForController(t)
	require.NoError(t, err)

	// Create clients
	k8sClient := fake.NewSimpleClientset(testK8sNode)
	kmeshClient := fakeKmeshClientset.NewSimpleClientset()

	// Patch kube.GetKmeshNodeInfoClient to return our fake client
	clientPatches := gomonkey.NewPatches()
	clientPatches.ApplyFuncReturn(kube.GetKmeshNodeInfoClient, kmeshClient, nil)
	defer clientPatches.Reset()

	prepare := func(t *testing.T) (*IPSecController, chan struct{}) {
		// Create mock eBPF components
		mockMap := &ebpf.Map{}
		mockProg := &ebpf.Program{}
		stopCh := make(chan struct{})
		controller, err := NewIPsecController(k8sClient, mockMap, mockProg)
		assert.NoError(t, err)
		assert.NotNil(t, controller)
		go controller.informer.Run(stopCh)
		if !cache.WaitForCacheSync(stopCh, controller.informer.HasSynced) {
			t.Fatal("timed out waiting for caches to sync")
		}
		return controller, stopCh
	}

	t.Run("createAndUpdateLocalKmeshNodeInfo", func(t *testing.T) {
		controller, stopCh := prepare(t)
		defer close(stopCh)
		// No node info
		node, err := controller.lister.KmeshNodeInfos("kmesh-system").Get("test-local-node")
		assert.Error(t, err)
		assert.Nil(t, node)

		err = controller.updateLocalKmeshNodeInfo()
		assert.NoError(t, err)

		// Wait for get node info
		err = wait.PollUntilContextTimeout(context.Background(), 20*time.Millisecond, 200*time.Millisecond, false, func(context.Context) (bool, error) {
			_, err := controller.lister.KmeshNodeInfos("kmesh-system").Get("test-local-node")
			return err == nil, nil
		})
		assert.NoError(t, err)

		node, err = controller.lister.KmeshNodeInfos("kmesh-system").Get("test-local-node")
		assert.NoError(t, err)
		assert.NotNil(t, node)
		assert.Equal(t, "test-local-node", node.Name)
		assert.Equal(t, 1, node.Spec.SPI) // should be same to testKey

		// Test update local node info
		// New node info
		controller.kmeshNodeInfo.Spec.SPI = 2

		err = controller.updateLocalKmeshNodeInfo()
		assert.NoError(t, err)

		// Wait for node info update
		err = wait.PollUntilContextTimeout(context.Background(), 20*time.Millisecond, 200*time.Millisecond, false, func(context.Context) (bool, error) {
			nodeinfo, err := controller.lister.KmeshNodeInfos("kmesh-system").Get("test-local-node")
			if nodeinfo != nil && nodeinfo.Spec.SPI == 2 {
				return true, nil
			}
			if err != nil {
				return false, err
			}
			return false, nil
		})
		assert.NoError(t, err)

		// lister can get new node info
		node, err = controller.lister.KmeshNodeInfos("kmesh-system").Get("test-local-node")
		assert.NoError(t, err)
		assert.NotNil(t, node)
		assert.Equal(t, 2, node.Spec.SPI) // new spi
	})

	t.Run("syncAllNodeInfo", func(t *testing.T) {
		controller, stopCh := prepare(t)
		defer close(stopCh)

		// Create remote node
		_, err = kmeshClient.KmeshV1alpha1().KmeshNodeInfos("kmesh-system").Create(context.TODO(), testRemoteNodeInfo, metav1.CreateOptions{})
		assert.NoError(t, err)

		// Patch handleOneNodeInfo
		syncPatch := gomonkey.NewPatches()
		syncPatch.ApplyPrivateMethod(reflect.TypeOf(controller), "handleOneNodeInfo", func(c *IPSecController, node *v1alpha1.KmeshNodeInfo) error {
			if node.Name == testRemoteNodeInfo.Name { // test if get remote node info and ignore local node info
				return nil
			}
			return fmt.Errorf("failed to get remote node info")
		})
		defer syncPatch.Reset()

		go controller.informer.Run(stopCh)
		if !cache.WaitForCacheSync(stopCh, controller.informer.HasSynced) {
			t.Fatal("timed out waiting for caches to sync")
		}

		err = controller.syncAllNodeInfo()
		assert.NoError(t, err)
	})

	// test handle testRemoteNodeInfo
	t.Run("handleOneNodeInfo", func(t *testing.T) {
		controller, stopCh := prepare(t)
		defer close(stopCh)

		patches := gomonkey.NewPatches()
		defer patches.Reset()
		podCIDRSet := make(map[string]bool)

		for _, podCIDR := range testRemoteNodeInfo.Spec.PodCIDRs {
			podCIDRSet[podCIDR] = true
		}
		patches.ApplyPrivateMethod(reflect.TypeOf(controller.ipsecHandler), "CreateXfrmRule", func(_ *IpSecHandler, localNode *v1alpha1.KmeshNodeInfo, remoteNode *v1alpha1.KmeshNodeInfo) error {
			// mock, remote node info should be same with testRemoteNodeInfo
			for _, podCIDR := range remoteNode.Spec.PodCIDRs {
				if !podCIDRSet[podCIDR] {
					return fmt.Errorf("remote node info podCIDRs is not equal")
				}
			}
			return nil
		})
		patches.ApplyPrivateMethod(reflect.TypeOf(controller), "updateKNIMapCIDR", func(c *IPSecController, remoteCIDR string, mapfd *ebpf.Map) error {
			// mock, remote node info should be same with testRemoteNodeInfo
			if !podCIDRSet[remoteCIDR] {
				return fmt.Errorf("remote node info podCIDRs is not equal")
			}
			return nil
		})

		patches.ApplyFunc(netns.WithNetNSPath, func(nspath string, toRun func(netns.NetNS) error) error {
			return nil
		})

		err = controller.handleOneNodeInfo(testRemoteNodeInfo)
		assert.NoError(t, err)
	})
}

func TestProcessNextItem(t *testing.T) {
	err := prepareForController(t)
	require.NoError(t, err)

	// Setup patches
	patches := gomonkey.NewPatches()
	defer patches.Reset()

	// Create clients
	k8sClient := fake.NewSimpleClientset(testK8sNode)
	kmeshClient := fakeKmeshClientset.NewSimpleClientset()

	// Apply patches for kube.GetKmeshNodeInfoClient to return our fake client
	clientPatches := gomonkey.NewPatches()
	clientPatches.ApplyFuncReturn(kube.GetKmeshNodeInfoClient, kmeshClient, nil)
	defer clientPatches.Reset()

	prepare := func(t *testing.T) (*IPSecController, chan struct{}) {
		// Create mock eBPF components
		mockMap := &ebpf.Map{}
		mockProg := &ebpf.Program{}

		controller, err := NewIPsecController(k8sClient, mockMap, mockProg)
		assert.NoError(t, err)
		assert.NotNil(t, controller)

		stopCh := make(chan struct{})
		go controller.informer.Run(stopCh)
		if !cache.WaitForCacheSync(stopCh, controller.informer.HasSynced) {
			t.Fatal("timed out waiting for caches to sync")
		}
		return controller, stopCh
	}

	t.Run("successful_processing", func(t *testing.T) {
		controller, stopCh := prepare(t)
		defer close(stopCh)

		// Add remote node to queue
		controller.queue.Add("test-remote-node")

		// Mock handleOneNodeInfo to avoid complex IPsec operations
		handlerPatches := gomonkey.NewPatches()
		handlerPatches.ApplyPrivateMethod(reflect.TypeOf(controller), "handleOneNodeInfo", func(_ *IPSecController, _ *v1alpha1.KmeshNodeInfo) error {
			return nil // Simulate success
		})
		defer handlerPatches.Reset()

		// Process the item
		result := controller.processNextItem()
		assert.True(t, result)                     // Should return true indicating continue processing
		assert.Equal(t, 0, controller.queue.Len()) // Item should be removed from queue
	})

	t.Run("non_existent_node", func(t *testing.T) {
		controller, stopCh := prepare(t)
		defer close(stopCh)

		// Test with non-existent node
		controller.queue.Add("non-existent-node")
		result := controller.processNextItem()
		controller.queue.Done("non-existent-node")
		assert.True(t, result)                     // Should still return true
		assert.Equal(t, 0, controller.queue.Len()) // Item should be removed from queue
	})

	// Test if the error returned by handleOneNodeInfo is not nil, the function should return true, and requeue the item or forget it based on the number of requeues
	t.Run("handleOneNodeInfo_err", func(t *testing.T) {
		controller, stopCh := prepare(t)
		defer close(stopCh)

		// Add local node to queue
		controller.queue.Add("test-local-node")
		failPatches := gomonkey.NewPatches()
		failPatches.ApplyPrivateMethod(reflect.TypeOf(controller), "handleOneNodeInfo", func(_ *IPSecController, _ *v1alpha1.KmeshNodeInfo) error {
			return fmt.Errorf("test error") // Simulate failure
		})
		defer failPatches.Reset()

		// Create local node info
		_, err = controller.knclient.Create(context.TODO(), &controller.kmeshNodeInfo, metav1.CreateOptions{})
		assert.NoError(t, err)

		// Wait
		err = wait.PollUntilContextTimeout(context.Background(), 20*time.Millisecond, 200*time.Millisecond, false, func(context.Context) (bool, error) {
			_, err := controller.lister.KmeshNodeInfos("kmesh-system").Get("test-local-node")
			return err == nil, nil
		})
		assert.NoError(t, err)

		for exceptRetryCount := 1; exceptRetryCount <= MaxRetries+1; exceptRetryCount++ {
			result := controller.processNextItem()
			assert.True(t, result) // Should still return true
			// NumRequeues("test-local-node") will return the number of times the item has been requeued
			// So, every time to call processNextItem, the number of requeues will increase by 1
			// When the number of requeues is greater than MaxRetries, the item will be forgotten
			assert.Equal(t, exceptRetryCount%(MaxRetries+1), controller.queue.NumRequeues("test-local-node"))
		}
	})
}

func TestHandleTc(t *testing.T) {
	err := prepareForController(t)
	require.NoError(t, err)

	// Setup patches
	patches := gomonkey.NewPatches()
	defer patches.Reset()

	// Create fake clients
	k8sClient := fake.NewSimpleClientset(testK8sNode)
	kmeshClient := fakeKmeshClientset.NewSimpleClientset()
	patches.ApplyFuncReturn(kube.GetKmeshNodeInfoClient, kmeshClient, nil)

	mockMap := &ebpf.Map{}
	mockProg := &ebpf.Program{}

	// Create controller
	controller, err := NewIPsecController(k8sClient, mockMap, mockProg)
	require.NoError(t, err)
	require.NotNil(t, controller)

	testCases := []struct {
		name           string
		mode           int
		mockInterfaces []net.Interface
		mockIfaceAddrs map[string][]net.Addr
		mockLinkByName map[string]netlink.Link
		expectedCalls  map[string]int // track expected calls to ManageTCProgram
		expectedError  bool
	}{
		{
			name: "successful_attach_tc_program",
			mode: constants.TC_ATTACH,
			mockInterfaces: []net.Interface{
				{Index: 1, Name: "eth0", Flags: net.FlagUp},
				{Index: 2, Name: "lo", Flags: net.FlagLoopback | net.FlagUp},
				{Index: 3, Name: "eth1", Flags: net.FlagUp},
			},
			mockLinkByName: map[string]netlink.Link{
				"eth0": &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 1}},
				"eth1": &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth1", Index: 3}},
			},
			expectedError: false,
		},
		{
			name: "successful_detach_tc_program",
			mode: constants.TC_DETACH,
			mockInterfaces: []net.Interface{
				{Index: 1, Name: "eth0", Flags: net.FlagUp},
			},
			mockLinkByName: map[string]netlink.Link{
				"eth0": &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "eth0", Index: 1}},
			},
			expectedError: false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			// mock Interfaces
			interfacesPatches := gomonkey.NewPatches()
			defer interfacesPatches.Reset()
			interfacesPatches.ApplyFunc(net.Interfaces, func() ([]net.Interface, error) {
				return test.mockInterfaces, nil
			})
			// mock IfaceContainIPs
			ifaceContainIPsPatches := gomonkey.NewPatches()
			defer ifaceContainIPsPatches.Reset()
			ifaceContainIPsPatches.ApplyFunc(utils.IfaceContainIPs, func(iface net.Interface, IPs []string) (bool, error) {
				return true, nil
			})

			// mock LinkByName
			linkByNamePatches := gomonkey.NewPatches()
			defer linkByNamePatches.Reset()
			linkByNamePatches.ApplyFunc(netlink.LinkByName, func(name string) (netlink.Link, error) {
				return test.mockLinkByName[name], nil
			})
			// mock ManageTCProgram
			manageTCProgramPatches := gomonkey.NewPatches()
			defer manageTCProgramPatches.Reset()
			manageTCProgramPatches.ApplyFunc(utils.ManageTCProgram, func(link netlink.Link, tc *ebpf.Program, mode int) error {
				return nil
			})
			err := controller.handleTc(test.mode)

			// Verify results
			if test.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
