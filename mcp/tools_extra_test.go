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
	"encoding/json"
	"strings"
	"testing"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func ipsecSecret(data map[string][]byte) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "kmesh-ipsec", Namespace: "kmesh-system"},
		Data:       data,
	}
}

func TestHandleGetIpsecStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("configured secret reports metadata but never the key", func(t *testing.T) {
		h := newTestHandler([]runtime.Object{ipsecSecret(map[string][]byte{
			"ipSec": []byte(`{"spi":2,"aeadKeyName":"rfc4106(gcm(aes))","aeadKey":"c2VjcmV0LWtleS1tYXRlcmlhbA==","length":36}`),
		})}, nil, nil)
		res, err := h.HandleGetIpsecStatus(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		var out map[string]any
		require.NoError(t, json.Unmarshal([]byte(text), &out))
		assert.Equal(t, true, out["configured"])
		assert.Equal(t, float64(2), out["spi"])
		assert.Equal(t, "rfc4106(gcm(aes))", out["aeadKeyName"])
		assert.NotContains(t, text, "c2VjcmV0LWtleS1tYXRlcmlhbA==")
		assert.NotContains(t, text, "secret-key-material")
	})

	t.Run("missing secret returns configured false with hint", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		res, err := h.HandleGetIpsecStatus(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, `"configured": false`)
		assert.Contains(t, text, "kmeshctl secret create")
	})

	t.Run("malformed ipSec key sets error field", func(t *testing.T) {
		h := newTestHandler([]runtime.Object{ipsecSecret(map[string][]byte{
			"ipSec": []byte(`{not-json`),
		})}, nil, nil)
		res, err := h.HandleGetIpsecStatus(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "malformed")
	})

	t.Run("missing ipSec key sets error field", func(t *testing.T) {
		h := newTestHandler([]runtime.Object{ipsecSecret(map[string][]byte{
			"other": []byte("x"),
		})}, nil, nil)
		res, err := h.HandleGetIpsecStatus(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "missing")
	})

	t.Run("invalid namespace rejected", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		res, err := h.HandleGetIpsecStatus(ctx, makeCallRequest(map[string]any{"namespace": "BAD NAME"}))
		require.NoError(t, err)
		assert.True(t, res.IsError)
	})
}

func TestHandleListMeshServices(t *testing.T) {
	ctx := context.Background()

	meshNs := func(name, labelValue string) *corev1.Namespace {
		return &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: map[string]string{"istio.io/dataplane-mode": labelValue},
		}}
	}
	svc := func(name, ns, ip string) *corev1.Service {
		return &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: corev1.ServiceSpec{
				ClusterIP: ip,
				Ports:     []corev1.ServicePort{{Port: 9080, Protocol: corev1.ProtocolTCP}},
				Selector:  map[string]string{"app": name},
			},
		}
	}

	t.Run("lists services across mesh namespaces case-insensitively", func(t *testing.T) {
		h := newTestHandler([]runtime.Object{
			meshNs("default", "kmesh"), meshNs("shop", "Kmesh"), meshNs("other", "istio"),
			svc("productpage", "default", "10.96.5.5"), svc("cart", "shop", "10.96.5.6"), svc("nope", "other", "10.96.5.7"),
		}, nil, nil)
		res, err := h.HandleListMeshServices(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		text := res.Content[0].(mcp.TextContent).Text
		assert.Contains(t, text, "productpage")
		assert.Contains(t, text, "cart")
		assert.NotContains(t, text, "nope")
		assert.Contains(t, text, "10.96.5.5")
		assert.Contains(t, text, "9080/TCP")
	})

	t.Run("specific namespace lists directly", func(t *testing.T) {
		h := newTestHandler([]runtime.Object{
			svc("reviews", "default", "10.96.5.8"),
		}, nil, nil)
		res, err := h.HandleListMeshServices(ctx, makeCallRequest(map[string]any{"namespace": "default"}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "reviews")
	})

	t.Run("no services returns hint", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		res, err := h.HandleListMeshServices(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "No services found")
	})

	t.Run("invalid namespace rejected", func(t *testing.T) {
		h := newTestHandler(nil, nil, nil)
		res, err := h.HandleListMeshServices(ctx, makeCallRequest(map[string]any{"namespace": "bad ns"}))
		require.NoError(t, err)
		assert.True(t, res.IsError)
	})
}

func bpfDetailStub(daemonMode string, payload string) func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
	return func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
		switch {
		case endpoint == "version":
			return []byte(`{"mode":"` + daemonMode + `"}`), nil
		case strings.Contains(endpoint, "debug/config_dump/bpf/"):
			return []byte(payload), nil
		}
		return nil, assert.AnError
	}
}

func TestHandleBpfDetailTools(t *testing.T) {
	ctx := context.Background()
	dump := `{"backends":[{"ip":"10.0.0.1","services":["default/productpage"]}]}`

	t.Run("workload details hits dual-engine endpoint", func(t *testing.T) {
		calls := []string{}
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			calls = append(calls, endpoint)
			return bpfDetailStub("dual-engine", dump)(ctx, podName, namespace, endpoint)
		})
		res, err := h.HandleBpfWorkloadDetails(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Equal(t, []string{"version", "debug/config_dump/bpf/dual-engine"}, calls)
	})

	t.Run("ads details hits kernel-native endpoint", func(t *testing.T) {
		calls := []string{}
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			calls = append(calls, endpoint)
			return bpfDetailStub("kernel-native", dump)(ctx, podName, namespace, endpoint)
		})
		res, err := h.HandleBpfAdsDetails(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.False(t, res.IsError)
		assert.Equal(t, []string{"version", "debug/config_dump/bpf/kernel-native"}, calls)
	})

	t.Run("mode mismatch points to the sibling tool", func(t *testing.T) {
		h := newTestHandler(nil, nil, bpfDetailStub("kernel-native", dump))
		res, err := h.HandleBpfWorkloadDetails(ctx, makeCallRequest(map[string]any{}))
		require.NoError(t, err)
		assert.True(t, res.IsError)
		assert.Contains(t, res.Content[0].(mcp.TextContent).Text, "get_bpf_ads_details")
	})

	t.Run("invalid pod name rejected before any fetch", func(t *testing.T) {
		h := newTestHandler(nil, nil, func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
			t.Fatal("fetch must not happen for invalid input")
			return nil, nil
		})
		res, err := h.HandleBpfWorkloadDetails(ctx, makeCallRequest(map[string]any{"podName": "bad name!"}))
		require.NoError(t, err)
		assert.True(t, res.IsError)
	})
}
