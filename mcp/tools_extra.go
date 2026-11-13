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
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ctlsecret "kmesh.net/kmesh/ctl/secret"
	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/constants"
)

// ipsecStatus is the safe view of the kmesh-ipsec secret; key material is never included.
type ipsecStatus struct {
	Configured  bool   `json:"configured"`
	SPI         int    `json:"spi,omitempty"`
	AeadKeyName string `json:"aeadKeyName,omitempty"`
	KeyLength   int    `json:"keyLength,omitempty"`
	CreatedAt   string `json:"createdAt,omitempty"`
	Error       string `json:"error,omitempty"`
	Hint        string `json:"hint,omitempty"`
	Note        string `json:"note,omitempty"`
}

type ipSecKeyFile struct {
	SPI         int    `json:"spi"`
	AeadKeyName string `json:"aeadKeyName"`
	AeadKey     []byte `json:"aeadKey"`
	Length      int    `json:"length"`
}

// HandleGetIpsecStatus reports whether IPsec encryption is configured.
func (h *McpHandler) HandleGetIpsecStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ns := req.GetString("namespace", "")
	if ns == "" {
		ns = utils.KmeshNamespace
	}
	if err := validateK8sName("namespace", ns); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	secret, err := h.cliClient.Kube().CoreV1().Secrets(ns).Get(ctx, ctlsecret.SecretName, metav1.GetOptions{})
	if err != nil {
		out := ipsecStatus{
			Configured: false,
			Hint:       "IPsec key not found. Create one with: kmeshctl secret create",
		}
		return marshalToolJSON(out)
	}

	out := ipsecStatus{
		Configured: true,
		CreatedAt:  secret.CreationTimestamp.String(),
		Note:       "Key material stays in the secret and is never exposed here.",
	}
	raw, ok := secret.Data["ipSec"]
	if !ok {
		out.Error = "secret exists but the 'ipSec' key is missing"
		return marshalToolJSON(out)
	}
	var key ipSecKeyFile
	if err := json.Unmarshal(raw, &key); err != nil {
		out.Error = "secret exists but the 'ipSec' key is malformed"
		return marshalToolJSON(out)
	}
	out.SPI = key.SPI
	out.AeadKeyName = key.AeadKeyName
	out.KeyLength = key.Length
	return marshalToolJSON(out)
}

type meshService struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	ClusterIP string   `json:"clusterIP"`
	Ports     []string `json:"ports"`
	Selector  string   `json:"selector,omitempty"`
}

// HandleListMeshServices lists Kubernetes services in mesh-enrolled namespaces.
func (h *McpHandler) HandleListMeshServices(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ns := req.GetString("namespace", "")
	if ns != "" {
		if err := validateK8sName("namespace", ns); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	namespaces := []string{}
	if ns != "" {
		namespaces = append(namespaces, ns)
	} else {
		list, err := h.cliClient.Kube().CoreV1().Namespaces().List(ctx, metav1.ListOptions{
			LabelSelector: constants.DataPlaneModeLabel,
		})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list namespaces: %v", err)), nil
		}
		for _, n := range list.Items {
			if strings.EqualFold(n.Labels[constants.DataPlaneModeLabel], constants.DataPlaneModeKmesh) {
				namespaces = append(namespaces, n.Name)
			}
		}
	}

	services := []meshService{}
	for _, n := range namespaces {
		list, err := h.cliClient.Kube().CoreV1().Services(n).List(ctx, metav1.ListOptions{})
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("Failed to list services in %s: %v", n, err)), nil
		}
		for _, svc := range list.Items {
			services = append(services, convertService(svc))
		}
	}

	out := map[string]any{"count": len(services), "services": services}
	if len(services) == 0 {
		out["hint"] = "No services found. Check namespace enrollment with get_mesh_namespaces."
	}
	return marshalToolJSON(out)
}

func convertService(svc corev1.Service) meshService {
	ports := make([]string, 0, len(svc.Spec.Ports))
	for _, p := range svc.Spec.Ports {
		ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
	}
	selectorParts := make([]string, 0, len(svc.Spec.Selector))
	for k, v := range svc.Spec.Selector {
		selectorParts = append(selectorParts, fmt.Sprintf("%s=%s", k, v))
	}
	sort.Strings(selectorParts)
	return meshService{
		Name:      svc.Name,
		Namespace: svc.Namespace,
		ClusterIP: svc.Spec.ClusterIP,
		Ports:     ports,
		Selector:  strings.Join(selectorParts, ","),
	}
}

// handleBpfDetail serves the mode-specific BPF deep-dive tools.
func (h *McpHandler) handleBpfDetail(ctx context.Context, req mcp.CallToolRequest, wantMode, endpoint, sibling string) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")
	summary := req.GetBool("summary", true)
	filter := req.GetString("filter", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	mode, err := h.detectMode(ctx, podName, namespace)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("could not verify daemon mode: %v", err)), nil
	}
	if mode != wantMode {
		return mcp.NewToolResultError(fmt.Sprintf("this tool requires %q mode but the daemon runs %q; use %s instead", wantMode, mode, sibling)), nil
	}

	raw, err := h.fetchFromDaemon(ctx, podName, namespace, endpoint)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch BPF details: %v", err)), nil
	}
	out, err := formatDump(raw, filter, summary)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to process BPF details: %v", err)), nil
	}
	return mcp.NewToolResultText(out), nil
}

// HandleBpfWorkloadDetails dives into dual-engine (workload) BPF maps.
func (h *McpHandler) HandleBpfWorkloadDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return h.handleBpfDetail(ctx, req, constants.DualEngineMode,
		"debug/config_dump/bpf/dual-engine", "get_bpf_ads_details")
}

// HandleBpfAdsDetails dives into kernel-native (ADS) BPF maps.
func (h *McpHandler) HandleBpfAdsDetails(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return h.handleBpfDetail(ctx, req, constants.KernelNativeMode,
		"debug/config_dump/bpf/kernel-native", "get_bpf_workload_details")
}

func marshalToolJSON(v any) (*mcp.CallToolResult, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to encode result: %v", err)), nil
	}
	return mcp.NewToolResultText(string(b)), nil
}
