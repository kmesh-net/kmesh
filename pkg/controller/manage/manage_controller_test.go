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

package kmeshmanage

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/containernetworking/plugins/pkg/ns"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"istio.io/istio/pkg/test/util/retry"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	podWithoutLabel = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "ut-pod",
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	podNotReadyWithoutLabel = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "ut-pod",
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	podWithLabel = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "ut-pod",
			Labels:    map[string]string{constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}
	podNotReadyWithLabel = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "ut-pod",
			Labels:    map[string]string{constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	podWithNoneLabel = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "ut-pod",
			Labels:    map[string]string{constants.DataPlaneModeLabel: "none"},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}
	podReadyWithAnnotation = &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "default",
			Name:      "ut-pod-1",
			Annotations: map[string]string{
				"kmesh.net/redirection": "enabled",
			},
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{
					Type:   corev1.PodReady,
					Status: corev1.ConditionTrue,
				},
			},
		},
	}

	nsWithoutLabel = &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	nsWithLabel = &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh},
		},
	}
)

func waitAndCheckManageAction(t *testing.T, enabled *atomic.Bool, disabled *atomic.Bool, enableExpected bool, disableExpected bool) {
	retry.UntilSuccess(func() error {
		// Wait for the handleKmeshManage to be called
		if enableExpected != enabled.Load() || disableExpected != disabled.Load() {
			return fmt.Errorf("enabled: %v, disabled: %v", enabled.Load(), disabled.Load())
		}
		return nil
	})
	assert.Equal(t, enableExpected, enabled.Load(), "unexpected value for enabled flag")
	assert.Equal(t, disableExpected, disabled.Load(), "unexpected value for disabled flag")
}

func TestHandleKmeshManage(t *testing.T) {
	client := fake.NewSimpleClientset()

	err := os.Setenv("NODE_NAME", "test_node")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	controller, err := NewKmeshManageController(client, nil, 0, -1, "")
	if err != nil {
		t.Fatalf("error creating KmeshManageController: %v", err)
	}
	stopChan := make(chan struct{})
	defer close(stopChan)

	go controller.Run(stopChan)
	cache.WaitForCacheSync(stopChan, controller.podInformer.HasSynced, controller.namespaceInformer.HasSynced)

	enabled := atomic.Bool{}
	disabled := atomic.Bool{}

	patches := gomonkey.NewPatches()
	defer patches.Reset()
	patches.ApplyFunc(utils.HandleKmeshManage, func(ns string, op bool) error {
		if op {
			enabled.Store(true)
		} else {
			disabled.Store(true)
		}
		return nil
	})

	patches.ApplyMethodFunc(reflect.TypeOf(controller.queue), "AddRateLimited", func(item interface{}) {
		queueItem, ok := item.(QueueItem)
		if !ok {
			t.Logf("expected QueueItem but got %T", item)
			return
		}
		pod, err := controller.podLister.Pods(queueItem.podNs).Get(queueItem.podName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				t.Logf("pod %s/%s has been deleted", queueItem.podNs, queueItem.podName)
				return
			}
			t.Errorf("failed to get pod %s/%s: %v", queueItem.podNs, queueItem.podName, err)
		}

		if pod != nil {
			namespace, _ := controller.namespaceLister.Get(pod.Namespace)
			if queueItem.action == ActionAddAnnotation && utils.ShouldEnroll(pod, namespace) {
				t.Logf("add annotation for pod %s/%s", pod.Namespace, pod.Name)
				err = utils.PatchKmeshRedirectAnnotation(controller.client, pod)
			} else if queueItem.action == ActionDeleteAnnotation && !utils.ShouldEnroll(pod, namespace) {
				t.Logf("delete annotation for pod %s/%s", pod.Namespace, pod.Name)
				err = utils.DelKmeshRedirectAnnotation(controller.client, pod)
			}
		}
		if err != nil {
			t.Errorf("failed to handle pod %s/%s: %v", queueItem.podNs, queueItem.podName, err)
		}
	})

	type args struct {
		namespace              *corev1.Namespace
		pod                    *corev1.Pod
		create, update, delete bool
	}
	tests := []struct {
		name             string
		args             args
		expectManaged    bool
		expectDisManaged bool
	}{
		{
			name: "1. ns without label, pod without label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithoutLabel,
				create:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "2. ns without label, pod update with label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithLabel,
				update:    true,
			},
			expectManaged:    true,
			expectDisManaged: false,
		},
		{
			name: "2.1 ns without label, pod update with `none` label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithNoneLabel,
				update:    true,
			},
			expectManaged:    false,
			expectDisManaged: true,
		},
		{
			name: "3. ns without label, pod with none label delete",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithNoneLabel,
				delete:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "4. ns without label, pod with label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithLabel,
				create:    true,
			},
			expectManaged: true,
		},
		{
			name: "4.1 ns without label, pod with label delete",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithLabel,
				delete:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},

		{
			name: "5. ns with label, pod without label",
			args: args{
				namespace: nsWithLabel,
				pod:       podWithoutLabel,
				create:    true,
			},
			expectManaged:    true,
			expectDisManaged: false,
		},
		{
			name: "6. ns with label, pod update with label",
			args: args{
				namespace: nsWithLabel,
				pod:       podWithLabel,
				update:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "7. ns with label, pod update with none label",
			args: args{
				namespace: nsWithLabel,
				pod:       podWithNoneLabel,
				update:    true,
			},
			expectManaged:    false,
			expectDisManaged: true,
		},
		{
			name: "8. ns with label, pod delete with none label",
			args: args{
				namespace: nsWithLabel,
				pod:       podWithNoneLabel,
				delete:    true,
			},
			expectDisManaged: false,
		},
		{
			name: "9. ns without label, pod is not ready with label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podNotReadyWithLabel,
				create:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "9.1. ns without label, pod is not ready update without label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podNotReadyWithoutLabel,
				update:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "10. ns without label, pod ready add without annotation",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podReadyWithAnnotation,
				create:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
	}

	_, err = client.CoreV1().Namespaces().Create(context.TODO(), nsWithoutLabel, metav1.CreateOptions{})
	assert.NoError(t, err)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err = client.CoreV1().Namespaces().Update(context.TODO(), tt.args.namespace, metav1.UpdateOptions{})
			assert.NoError(t, err)
			// TODO: find a way to wait for namespace informer to sync
			time.Sleep(5 * time.Millisecond)

			enabled.Store(false)
			disabled.Store(false)

			if tt.args.create {
				pod := tt.args.pod.DeepCopy()
				_, err = client.CoreV1().Pods(tt.args.namespace.Name).Create(context.TODO(), pod, metav1.CreateOptions{})
				assert.NoError(t, err)
			}

			if tt.args.update {
				pod, _ := client.CoreV1().Pods(tt.args.namespace.Name).Get(context.TODO(), tt.args.pod.Name, metav1.GetOptions{})
				if pod != nil {
					pod.Labels = tt.args.pod.Labels
				}
				_, err = client.CoreV1().Pods(tt.args.namespace.Name).Update(context.TODO(), pod, metav1.UpdateOptions{})
				assert.NoError(t, err)
			}

			if tt.args.delete {
				err = client.CoreV1().Pods(tt.args.namespace.Name).Delete(context.TODO(), tt.args.pod.Name, metav1.DeleteOptions{})
				assert.NoError(t, err)
			}

			waitAndCheckManageAction(t, &enabled, &disabled, tt.expectManaged, tt.expectDisManaged)
		})
	}
}

func TestNsInformerHandleKmeshManage(t *testing.T) {
	client := fake.NewSimpleClientset()

	err := os.Setenv("NODE_NAME", "test_node")
	require.NoError(t, err)
	t.Cleanup(func() {
		os.Unsetenv("NODE_NAME")
	})
	controller, err := NewKmeshManageController(client, nil, 0, -1, "")
	if err != nil {
		t.Fatalf("error creating KmeshManageController: %v", err)
	}

	stopChan := make(chan struct{})
	defer close(stopChan)

	go controller.Run(stopChan)
	cache.WaitForCacheSync(stopChan, controller.podInformer.HasSynced, controller.namespaceInformer.HasSynced)

	enabled := atomic.Bool{}
	disabled := atomic.Bool{}

	patches := gomonkey.NewPatches()
	defer patches.Reset()
	patches.ApplyFunc(utils.HandleKmeshManage, func(ns string, op bool) error {
		if op {
			enabled.Store(true)
		} else {
			disabled.Store(true)
		}
		return nil
	})

	patches.ApplyMethodFunc(reflect.TypeOf(controller.queue), "AddRateLimited", func(item interface{}) {
		queueItem, ok := item.(QueueItem)
		if !ok {
			t.Logf("expected QueueItem but got %T", item)
			return
		}
		pod, err := controller.podLister.Pods(queueItem.podNs).Get(queueItem.podName)
		if err != nil {
			if apierrors.IsNotFound(err) {
				t.Logf("pod %s/%s has been deleted", queueItem.podNs, queueItem.podName)
				return
			}
			t.Errorf("failed to get pod %s/%s: %v", queueItem.podNs, queueItem.podName, err)
		}

		if pod != nil {
			namespace, _ := controller.namespaceLister.Get(pod.Namespace)
			if queueItem.action == ActionAddAnnotation && utils.ShouldEnroll(pod, namespace) {
				t.Logf("add annotation for pod %s/%s", pod.Namespace, pod.Name)
				err = utils.PatchKmeshRedirectAnnotation(controller.client, pod)
			} else if queueItem.action == ActionDeleteAnnotation && !utils.ShouldEnroll(pod, namespace) {
				t.Logf("delete annotation for pod %s/%s", pod.Namespace, pod.Name)
				err = utils.DelKmeshRedirectAnnotation(controller.client, pod)
			}
		}
		if err != nil {
			t.Errorf("failed to handle pod %s/%s: %v", queueItem.podNs, queueItem.podName, err)
		}
	})

	type args struct {
		namespace      *corev1.Namespace
		pod            *corev1.Pod
		create, update bool
	}
	tests := []struct {
		name             string
		args             args
		expectManaged    bool
		expectDisManaged bool
	}{
		{
			name: "1. default ns add without label, pod without label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithoutLabel,
				create:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "1.1. default ns update with label, pod without label",
			args: args{
				namespace: nsWithLabel,
				pod:       podWithoutLabel,
				update:    true,
			},
			expectManaged:    true,
			expectDisManaged: false,
		},
		{
			name: "1.2. default ns update without label, pod without label",
			args: args{
				namespace: nsWithoutLabel,
				pod:       podWithoutLabel,
				update:    true,
			},
			expectManaged:    false,
			expectDisManaged: true,
		},
		{
			name: "2. foo ns add without label, pod with none label",
			args: args{
				namespace: nsObject("foo", false),
				pod:       podObject("pod", "foo", "none"),
				create:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "2.1. foo ns update with label, pod with none label",
			args: args{
				namespace: nsObject("foo", true),
				pod:       podObject("pod", "foo", "none"),
				update:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
		{
			name: "2.2. foo ns update without label, pod with none label",
			args: args{
				namespace: nsObject("foo", false),
				pod:       podObject("pod", "foo", "none"),
				update:    true,
			},
			expectManaged:    false,
			expectDisManaged: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// TODO: find a way to wait for namespace informer to sync
			time.Sleep(5 * time.Millisecond)

			enabled.Store(false)
			disabled.Store(false)

			if tt.args.create {
				pod := tt.args.pod.DeepCopy()
				_, err = client.CoreV1().Namespaces().Create(context.TODO(), tt.args.namespace, metav1.CreateOptions{})
				assert.NoError(t, err)
				_, err = client.CoreV1().Pods(tt.args.namespace.Name).Create(context.TODO(), pod, metav1.CreateOptions{})

				assert.NoError(t, err)
			}

			if tt.args.update {
				namespace, _ := client.CoreV1().Namespaces().Get(context.TODO(), tt.args.namespace.Name, metav1.GetOptions{})
				if namespace != nil {
					namespace.Labels = tt.args.namespace.Labels
				}
				_, err = client.CoreV1().Namespaces().Update(context.TODO(), namespace, metav1.UpdateOptions{})
				assert.NoError(t, err)
			}
			waitAndCheckManageAction(t, &enabled, &disabled, tt.expectManaged, tt.expectDisManaged)
		})
	}
}

func nsObject(name string, managed bool) *corev1.Namespace {
	ns := &corev1.Namespace{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Namespace",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
		},
	}

	if managed {
		ns.Labels = map[string]string{constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh}
	}

	return ns
}

func podObject(name string, namespace string, dataplaneLabel string) *corev1.Pod {
	pod := &corev1.Pod{
		TypeMeta: metav1.TypeMeta{
			Kind:       "Pod",
			APIVersion: "v1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
		},
		Spec: corev1.PodSpec{
			NodeName: "test-node",
		},
	}

	if dataplaneLabel != "" {
		pod.Labels = map[string]string{constants.DataPlaneModeLabel: dataplaneLabel}
	}

	return pod
}

func newTextXdpProg(t *testing.T, name string) *ebpf.Program {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.XDP,
		Name: name,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		prog.Close()
	})
	return prog
}

// Create a test netns, link an old XDP program on veth0 created inside the netns
func newTestNetNs(t *testing.T) ns.NetNS {
	testNs, err := ns.GetCurrentNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		testNs.Close()
	})

	testNs.Do(func(_ ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			netlink.LinkDel(veth)
		})
		prog := newTextXdpProg(t, "old_xdp")
		err := netlink.LinkSetXdpFd(veth, prog.FD())
		if err != nil {
			t.Fatal(err)
		}

		return nil
	})

	return testNs
}

// Test link a new XDP program on an linked interface
func Test_linkXdp(t *testing.T) {
	patches := gomonkey.NewPatches()
	defer patches.Reset()
	testNetNs := newTestNetNs(t)
	patches.ApplyFunc(ns.GetNS, func(_ string) (ns.NetNS, error) {
		return testNetNs, nil
	})

	type args struct {
		netNsPath string
		xdpProgFd int
		mode      string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Link a new XDP program, no error",
			args{
				"test_ns_path",
				newTextXdpProg(t, "new_xdp").FD(),
				constants.DualEngineMode,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := linkXdp(tt.args.netNsPath, tt.args.xdpProgFd, tt.args.mode); (err != nil) != tt.wantErr {
				t.Errorf("linkXdp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test unlink a new XDP program on an linked interface
func Test_unlinkXdp(t *testing.T) {
	patches := gomonkey.NewPatches()
	defer patches.Reset()
	testNetNs := newTestNetNs(t)
	patches.ApplyFunc(ns.GetNS, func(_ string) (ns.NetNS, error) {
		return testNetNs, nil
	})

	type args struct {
		netNsPath string
		mode      string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"UnLink XDP program, no error",
			args{
				"test_ns_path",
				constants.DualEngineMode,
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := unlinkXdp(tt.args.netNsPath, tt.args.mode); (err != nil) != tt.wantErr {
				t.Errorf("unlinkXdp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Create a test netns, link an old TC program on veth0 created inside the netns
func newTestNetNsWithVethPeerIndex(t *testing.T) (uint64, ns.NetNS, ns.NetNS) {
	var targetIndex uint64 = 0
	testNs1, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	testNs2, err := ns.TempNetNS()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if testNs1 != nil {
			testNs1.Close()
		}
		if testNs2 != nil {
			testNs1.Close()
		}
	})

	testNs1.Do(func(_ ns.NetNS) error {
		veth := &netlink.Veth{
			LinkAttrs: netlink.LinkAttrs{Name: "veth0"},
			PeerName:  "veth1",
		}
		if err := netlink.LinkAdd(veth); err != nil {
			t.Fatal(err)
		}
		if err := netlink.LinkSetUp(veth); err != nil {
			t.Fatal(err)
		}
		peer, err := netlink.LinkByName("veth1")
		if err != nil {
			t.Fatal(err)
		}
		if err = netlink.LinkSetNsFd(peer, int(testNs2.Fd())); err != nil {
			t.Fatal(err)
		}
		if err = netlink.LinkSetUp(veth); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			netlink.LinkDel(veth)
		})
		return nil
	})

	testNs2.Do(func(_ ns.NetNS) error {
		peer, err := netlink.LinkByName("veth1")
		if err != nil {
			t.Fatal(err)
		}
		if err = netlink.LinkSetUp(peer); err != nil {
			t.Fatal(err)
		}

		targetIndex = uint64(peer.Attrs().Index)

		t.Cleanup(func() {
			netlink.LinkDel(peer)
		})
		return nil
	})

	return targetIndex, testNs1, testNs2
}

func Test_getVethPeerNum(t *testing.T) {
	patches := gomonkey.NewPatches()
	defer patches.Reset()
	targetIndex, testNetNs, _ := newTestNetNsWithVethPeerIndex(t)
	patches.ApplyFunc(ns.GetNS, func(_ string) (ns.NetNS, error) {
		return testNetNs, nil
	})

	tests := []struct {
		name      string
		netNsPath string
		wantErr   bool
	}{
		{
			name:      "get veth peer index, no error",
			netNsPath: "test_ns_path",
			wantErr:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ifIndex uint64
			var err error
			warpGetVethPeerIndex := func(_ netns.NetNS) error {
				ifIndex, err = getVethPeerIndex()
				return err
			}

			if err = netns.WithNetNSPath(tt.netNsPath, warpGetVethPeerIndex); err != nil || ifIndex != targetIndex {
				t.Errorf("getVethPeerIndex() error = %v, ifIndex = %v, wantIndex = %v, wantErr %v", err, ifIndex, targetIndex, tt.wantErr)
			}
		})
	}
}

func newTextTcProg(t *testing.T, name string) *ebpf.Program {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Name: name,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		prog.Close()
	})
	return prog
}

func Test_TC(t *testing.T) {
	patches := gomonkey.NewPatches()
	defer patches.Reset()
	_, testNetNs1, testNetNs2 := newTestNetNsWithVethPeerIndex(t)
	patches.ApplyFunc(ns.WithNetNSPath, func(nspath string, toRun func(ns.NetNS) error) error {
		if nspath == "test_netns1" {
			return testNetNs1.Do(toRun)
		}
		if nspath == "test_netns2" {
			return testNetNs2.Do(toRun)
		}
		return nil
	})
	patches.ApplyFunc(utils.ManageTCProgramByFd, func(link netlink.Link, tcFd int, mode int) error {
		return nil
	})
	type args struct {
		netNsPath1 string
		netNsPath2 string
		tcProgFd   int
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"Link a new tc program, no error",
			args{
				"test_netns1",
				"test_netns2",
				newTextTcProg(t, "new_tc").FD(),
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warpFunc := func(netns.NetNS) error {
				if err := linkTc(tt.args.netNsPath1, tt.args.tcProgFd); (err != nil) != tt.wantErr {
					t.Errorf("linkTc() error = %v, wantErr %v", err, tt.wantErr)
				}
				if err := unlinkTc(tt.args.netNsPath1, tt.args.tcProgFd); (err != nil) != tt.wantErr {
					t.Errorf("unlinkTc() error = %v, wantErr %v", err, tt.wantErr)
				}
				return nil
			}
			if err := netns.WithNetNSPath(tt.args.netNsPath2, warpFunc); err != nil {
				t.Errorf("failed")
			}
		})
	}
}
