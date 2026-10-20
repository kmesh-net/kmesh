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

package mcp

import (
	"context"
	"fmt"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	istioconstants "istio.io/istio/pkg/config/constants"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	k8sfake "k8s.io/client-go/kubernetes/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayapiclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"

	"kmesh.net/kmesh/pkg/kube"
)

type fakeCLIClient struct {
	kubeClient    kubernetes.Interface
	gatewayClient gatewayapiclient.Interface
}

func (f *fakeCLIClient) Kube() kubernetes.Interface {
	return f.kubeClient
}

func (f *fakeCLIClient) GatewayAPI() gatewayapiclient.Interface {
	return f.gatewayClient
}

func (f *fakeCLIClient) PodsForSelector(ctx context.Context, namespace string, labelSelectors ...string) (*corev1.PodList, error) {
	return nil, nil
}

func (f *fakeCLIClient) NewPortForwarder(podName string, ns string, localAddress string, localPort int, podPort int) (kube.PortForwarder, error) {
	panic("unexpected call to NewPortForwarder in unit tests")
}

func newTestHandler(k8sObjs []runtime.Object, gwObjs []runtime.Object, fetchStub func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error)) *McpHandler {
	kClient := k8sfake.NewSimpleClientset(k8sObjs...)
	gwClient := gwfake.NewSimpleClientset()
	ctx := context.Background()
	for _, obj := range gwObjs {
		if gw, ok := obj.(*gatewayv1.Gateway); ok {
			ns := gw.Namespace
			if ns == "" {
				ns = "default"
			}
			_, _ = gwClient.GatewayV1().Gateways(ns).Create(ctx, gw, metav1.CreateOptions{})
		}
	}
	return &McpHandler{
		cliClient: &fakeCLIClient{
			kubeClient:    kClient,
			gatewayClient: gwClient,
		},
		fetch: fetchStub,
	}
}

func makeCallRequest(args map[string]any) mcp.CallToolRequest {
	return mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Arguments: args,
		},
	}
}

func TestGetDefaultDaemonPod(t *testing.T) {
	ctx := context.Background()

	t.Run("no pods found", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		_, err := h.getDefaultDaemonPod(ctx, "kmesh-system")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "no kmesh daemon pods found")
	})

	t.Run("pods found but none ready", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kmesh-daemon-pending",
				Namespace: "kmesh-system",
				Labels:    map[string]string{"app": "kmesh"},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
			},
		}
		h := newTestHandler([]runtime.Object{pod}, nil, nil)
		_, err := h.getDefaultDaemonPod(ctx, "kmesh-system")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "none are ready")
	})

	t.Run("prefers ready pod over pending first item", func(t *testing.T) {
		pendingPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kmesh-daemon-01",
				Namespace: "kmesh-system",
				Labels:    map[string]string{"app": "kmesh"},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodPending,
			},
		}
		readyPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kmesh-daemon-02",
				Namespace: "kmesh-system",
				Labels:    map[string]string{"app": "kmesh"},
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				Conditions: []corev1.PodCondition{
					{
						Type:   corev1.PodReady,
						Status: corev1.ConditionTrue,
					},
				},
			},
		}
		h := newTestHandler([]runtime.Object{pendingPod, readyPod}, nil, nil)
		podName, err := h.getDefaultDaemonPod(ctx, "kmesh-system")
		require.NoError(t, err)
		assert.Equal(t, "kmesh-daemon-02", podName)
	})
}

func TestHandleGetVersion(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			assert.Equal(t, "version", endpoint)
			return []byte(`{"gitVersion":"v0.5.0","mode":"kernel-native"}`), nil
		})

		req := makeCallRequest(map[string]any{"podName": "kmesh-pod", "namespace": "kmesh-system"})
		res, err := h.HandleGetVersion(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "v0.5.0")
	})

	t.Run("malformed podName", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{"podName": "BAD_NAME%%%", "namespace": "kmesh-system"})
		res, err := h.HandleGetVersion(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "invalid podName")
	})

	t.Run("daemon error", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			return nil, fmt.Errorf("connection refused")
		})
		req := makeCallRequest(map[string]any{"podName": "kmesh-pod"})
		res, err := h.HandleGetVersion(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "connection refused")
	})
}

func TestHandleConfigDump(t *testing.T) {
	ctx := context.Background()

	t.Run("valid mode hits mode endpoint", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			assert.Equal(t, "debug/config_dump/kernel-native", endpoint)
			return []byte(`{"configs":[]}`), nil
		})
		req := makeCallRequest(map[string]any{
			"podName": "kmesh-pod",
			"mode":    "kernel-native",
			"summary": true,
		})
		res, err := h.HandleConfigDump(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
	})

	t.Run("invalid mode rejected without fetch", func(t *testing.T) {
		fetchCalled := false
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			fetchCalled = true
			return nil, nil
		})
		req := makeCallRequest(map[string]any{"mode": "bad-mode"})
		res, err := h.HandleConfigDump(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.False(t, fetchCalled)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "mode must be")
	})

	t.Run("summary and filter routing", func(t *testing.T) {
		dump := `{
			"dynamic_active_clusters": [
				{"cluster": {"name": "outbound|80||productpage.default.svc.cluster.local"}},
				{"cluster": {"name": "outbound|80||reviews.default.svc.cluster.local"}}
			]
		}`
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			return []byte(dump), nil
		})
		req := makeCallRequest(map[string]any{
			"filter": "productpage",
		})
		res, err := h.HandleConfigDump(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "productpage")
		assert.NotContains(t, text, "reviews")
	})
}

func TestHandleBpfDump(t *testing.T) {
	ctx := context.Background()

	t.Run("auto-detect mode via version", func(t *testing.T) {
		calls := []string{}
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			calls = append(calls, endpoint)
			if endpoint == "version" {
				return []byte(`{"mode":"dual-engine"}`), nil
			}
			return []byte(`{"map_name":"test","entries":[]}`), nil
		})
		req := makeCallRequest(map[string]any{"podName": "kmesh-pod"})
		res, err := h.HandleBpfDump(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Equal(t, []string{"version", "debug/config_dump/bpf/dual-engine"}, calls)
	})

	t.Run("fallback to kernel-native when version fails", func(t *testing.T) {
		calls := []string{}
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			calls = append(calls, endpoint)
			if endpoint == "version" {
				return nil, fmt.Errorf("timeout")
			}
			return []byte(`{"entries":[]}`), nil
		})
		req := makeCallRequest(map[string]any{"podName": "kmesh-pod"})
		res, err := h.HandleBpfDump(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Equal(t, []string{"version", "debug/config_dump/bpf/kernel-native"}, calls)
	})

	t.Run("invalid mode rejected", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{"mode": "invalid-mode"})
		res, err := h.HandleBpfDump(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "mode must be")
	})
}

func TestHandleGetAuthzStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			assert.Equal(t, "authz", endpoint)
			return []byte(`{"enabled":true}`), nil
		})
		req := makeCallRequest(map[string]any{"podName": "kmesh-pod"})
		res, err := h.HandleGetAuthzStatus(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, `"enabled":true`)
	})

	t.Run("daemon failure", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			return nil, fmt.Errorf("daemon returned status 500")
		})
		req := makeCallRequest(map[string]any{"podName": "kmesh-pod"})
		res, err := h.HandleGetAuthzStatus(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
	})
}

func TestHandleGetDaemonHealth(t *testing.T) {
	ctx := context.Background()

	t.Run("ready success", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			assert.Equal(t, "debug/ready", endpoint)
			return []byte("ready"), nil
		})
		req := makeCallRequest(map[string]any{"podName": "kmesh-pod"})
		res, err := h.HandleGetDaemonHealth(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "Pod is READY")
	})

	t.Run("probe failure", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			return nil, fmt.Errorf("connection refused")
		})
		req := makeCallRequest(map[string]any{"podName": "kmesh-pod"})
		res, err := h.HandleGetDaemonHealth(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "Health check failed")
	})
}

func TestHandleGetLoggerLevels(t *testing.T) {
	ctx := context.Background()

	t.Run("without logger name", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			assert.Equal(t, "debug/loggers", endpoint)
			return []byte("bpf: debug"), nil
		})
		req := makeCallRequest(map[string]any{})
		res, err := h.HandleGetLoggerLevels(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Equal(t, "bpf: debug", res.Content[0].(mcp.TextContent).Text)
	})

	t.Run("with escaped logger name", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			assert.Equal(t, "debug/loggers?name=bpf%26workload", endpoint)
			return []byte("bpf&workload: info"), nil
		})
		req := makeCallRequest(map[string]any{"loggerName": "bpf&workload"})
		res, err := h.HandleGetLoggerLevels(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
	})
}

func TestHandleListDaemonPods(t *testing.T) {
	ctx := context.Background()

	t.Run("lists active pods", func(t *testing.T) {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kmesh-daemon-abc",
				Namespace: "kmesh-system",
				Labels:    map[string]string{"app": "kmesh"},
			},
			Spec: corev1.PodSpec{
				NodeName: "node-1",
			},
			Status: corev1.PodStatus{
				Phase: corev1.PodRunning,
				PodIP: "10.244.0.5",
			},
		}
		h := newTestHandler([]runtime.Object{pod}, nil, nil)
		req := makeCallRequest(map[string]any{})
		res, err := h.HandleListDaemonPods(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "kmesh-daemon-abc")
		assert.Contains(t, text, "node-1")
		assert.Contains(t, text, "10.244.0.5")
	})

	t.Run("empty pods informational text", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{"namespace": "kmesh-system"})
		res, err := h.HandleListDaemonPods(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "No Kmesh daemon pods found")
	})

	t.Run("malformed namespace", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{"namespace": "BAD/NS"})
		res, err := h.HandleListDaemonPods(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
	})
}

func TestHandleGetMeshNamespaces(t *testing.T) {
	ctx := context.Background()

	t.Run("lists mesh enabled namespaces", func(t *testing.T) {
		ns1 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name:   "default",
				Labels: map[string]string{"istio.io/dataplane-mode": "Kmesh"},
			},
		}
		ns2 := &corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: "kube-system",
			},
		}
		h := newTestHandler([]runtime.Object{ns1, ns2}, nil, nil)
		req := makeCallRequest(map[string]any{})
		res, err := h.HandleGetMeshNamespaces(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "default")
		assert.NotContains(t, text, "kube-system")
	})

	t.Run("empty namespaces informational text", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{})
		res, err := h.HandleGetMeshNamespaces(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "No namespaces found with label")
	})
}

func TestHandleListWaypoints(t *testing.T) {
	ctx := context.Background()

	wpGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "waypoint-01",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: gatewayv1.ObjectName(istioconstants.WaypointGatewayClassName),
		},
	}
	otherGateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ingress-01",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "istio-ingress",
		},
	}

	t.Run("filters only waypoint gateways", func(t *testing.T) {
		h := newTestHandler(nil, []runtime.Object{wpGateway, otherGateway}, nil)
		req := makeCallRequest(map[string]any{"namespace": "default"})
		res, err := h.HandleListWaypoints(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "waypoint-01")
		assert.NotContains(t, text, "ingress-01")
	})

	t.Run("empty waypoints text", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{"namespace": "default"})
		res, err := h.HandleListWaypoints(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "No Waypoint Gateways found")
	})
}

func TestHandleGetWaypointStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("renders conditions", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-waypoint",
				Namespace: "default",
			},
			Status: gatewayv1.GatewayStatus{
				Conditions: []metav1.Condition{
					{
						Type:   string(gatewayv1.GatewayConditionProgrammed),
						Status: metav1.ConditionTrue,
						Reason: "Programmed",
					},
				},
			},
		}
		h := newTestHandler(nil, []runtime.Object{gw}, nil)
		req := makeCallRequest(map[string]any{
			"name":      "my-waypoint",
			"namespace": "default",
		})
		res, err := h.HandleGetWaypointStatus(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "Programmed")
		assert.Contains(t, text, "True")
	})

	t.Run("zero conditions reported", func(t *testing.T) {
		gw := &gatewayv1.Gateway{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "fresh-waypoint",
				Namespace: "default",
			},
		}
		h := newTestHandler(nil, []runtime.Object{gw}, nil)
		req := makeCallRequest(map[string]any{
			"name": "fresh-waypoint",
		})
		res, err := h.HandleGetWaypointStatus(ctx, req)
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "(no conditions reported yet)")
	})

	t.Run("missing name argument", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{})
		res, err := h.HandleGetWaypointStatus(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "name argument is required")
	})

	t.Run("not found", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		req := makeCallRequest(map[string]any{"name": "non-existent"})
		res, err := h.HandleGetWaypointStatus(ctx, req)
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "Waypoint not found")
	})
}

func TestServerTransportValidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	h := newTestHandler(nil, nil, nil)

	err := RegisterToolsAndServe(ctx, h.cliClient, "invalid-transport")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid transport")
}

func TestFetchFromDaemonNoPods(t *testing.T) {
	ctx := context.Background()
	h := newTestHandler(nil, nil, nil) // fetch == nil
	_, err := h.fetchFromDaemon(ctx, "", "kmesh-system", "version")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no kmesh daemon pods found")
}

func TestValidateK8sNameHelper(t *testing.T) {
	assert.NoError(t, validateK8sName("pod", "valid-name"))
	assert.NoError(t, validateK8sName("pod", ""))
	assert.Error(t, validateK8sName("pod", "INVALID_NAME"))
	assert.Error(t, validateK8sName("pod", "name/with/slash"))
}

func TestMoreErrorPaths(t *testing.T) {
	ctx := context.Background()
	h := newTestHandler(nil, nil, nil)

	res, err := h.HandleGetAuthzStatus(ctx, makeCallRequest(map[string]any{"podName": "BAD/NAME"}))
	require.NoError(t, err)
	assert.True(t, res.IsError)

	res, err = h.HandleGetDaemonHealth(ctx, makeCallRequest(map[string]any{"podName": "BAD/NAME"}))
	require.NoError(t, err)
	assert.True(t, res.IsError)

	res, err = h.HandleGetLoggerLevels(ctx, makeCallRequest(map[string]any{"podName": "BAD/NAME"}))
	require.NoError(t, err)
	assert.True(t, res.IsError)

	res, err = h.HandleListWaypoints(ctx, makeCallRequest(map[string]any{"namespace": "BAD/NS"}))
	require.NoError(t, err)
	assert.True(t, res.IsError)
}

func TestHandleConfigDumpRaw(t *testing.T) {
	ctx := context.Background()
	dump := `{"listeners":[{"name":"0.0.0.0_15001"}]}`
	h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
		return []byte(dump), nil
	})
	req := makeCallRequest(map[string]any{
		"summary": false,
	})
	res, err := h.HandleConfigDump(ctx, req)
	require.NoError(t, err)
	assert.False(t, res.IsError)
	assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "0.0.0.0_15001")
}

func TestHandleBpfDumpRaw(t *testing.T) {
	ctx := context.Background()
	dump := `{"map_name":"test","entries":[{"key":1,"value":2}]}`
	h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
		return []byte(dump), nil
	})
	req := makeCallRequest(map[string]any{
		"mode":    "kernel-native",
		"summary": false,
	})
	res, err := h.HandleBpfDump(ctx, req)
	require.NoError(t, err)
	assert.False(t, res.IsError)
	assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "entries")
}

func TestServerStdioTransportCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so Listen returns immediately

	h := newTestHandler(nil, nil, nil)
	_ = RegisterToolsAndServe(ctx, h.cliClient, "stdio")
}
