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
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/kube"
)

// McpHandler holds the Kubernetes CLI Client to safely tunnel connections.
type McpHandler struct {
	cliClient kube.CLIClient
}

// getDefaultDaemonPod finds the first active kmesh-daemon pod if none is provided.
func (h *McpHandler) getDefaultDaemonPod(ctx context.Context, namespace string) (string, error) {
	if namespace == "" {
		namespace = "kmesh-system"
	}
	pods, err := h.cliClient.Kube().CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "app=kmesh",
	})
	if err != nil {
		return "", fmt.Errorf("failed to list kmesh pods: %v", err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no kmesh daemon pods found in namespace %s", namespace)
	}
	return pods.Items[0].Name, nil
}

// fetchFromDaemon sets up a secure port-forward to the target daemon pod
// and fetches data from the given endpoint (port 15200).
func (h *McpHandler) fetchFromDaemon(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
	if namespace == "" {
		namespace = "kmesh-system"
	}
	if podName == "" {
		defaultPod, err := h.getDefaultDaemonPod(ctx, namespace)
		if err != nil {
			return nil, err
		}
		podName = defaultPod
	}

	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fw, err := utils.CreateKmeshPortForwarder(h.cliClient, podName)
	if err != nil {
		return nil, fmt.Errorf("failed to create port-forward to %s: %w", podName, err)
	}

	if err := fw.Start(); err != nil {
		return nil, fmt.Errorf("failed to start forward: %w", err)
	}
	// Important: Guaranteed cleanup to prevent socket leaks
	defer fw.Close()

	url := fmt.Sprintf("http://%s/%s", fw.Address(), endpoint)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func condenseJsonDump(raw []byte, maxSize int) string {
	if len(raw) > maxSize {
		return string(raw[:maxSize]) + "\n... [WARNING: TRUNCATED due to length. Use specific filters to drill down]"
	}
	return string(raw)
}

func (h *McpHandler) HandleBpfDump(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")
	mode := req.GetString("mode", "")

	if mode != constants.KernelNativeMode && mode != constants.DualEngineMode {
		return mcp.NewToolResultError(fmt.Sprintf("mode must be %q or %q, got %q",
			constants.KernelNativeMode, constants.DualEngineMode, mode)), nil
	}

	endpoint := fmt.Sprintf("debug/config_dump/bpf/%s", mode)
	raw, err := h.fetchFromDaemon(ctx, podName, namespace, endpoint)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch BPF maps: %v", err)), nil
	}

	return mcp.NewToolResultText(condenseJsonDump(raw, 50*1024)), nil
}

func (h *McpHandler) HandleGetVersion(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	raw, err := h.fetchFromDaemon(ctx, podName, "kmesh-system", "version")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func (h *McpHandler) HandleConfigDump(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	mode := req.GetString("mode", "")

	endpoint := "debug/config_dump"
	if mode != "" {
		endpoint = fmt.Sprintf("debug/config_dump/%s", mode)
	}

	raw, err := h.fetchFromDaemon(ctx, podName, "kmesh-system", endpoint)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(condenseJsonDump(raw, 50*1024)), nil
}

func (h *McpHandler) HandleGetAuthzStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	raw, err := h.fetchFromDaemon(ctx, podName, "kmesh-system", "authz")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func (h *McpHandler) HandleGetDaemonHealth(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	raw, err := h.fetchFromDaemon(ctx, podName, "kmesh-system", "debug/ready")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Health check failed: %v", err)), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Pod is READY. Response: %s", string(raw))), nil
}

func (h *McpHandler) HandleGetLoggerLevels(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	loggerName := req.GetString("loggerName", "")

	endpoint := "debug/loggers"
	if loggerName != "" {
		// The name arrives from the MCP client, so it has to be escaped the same
		// way `kmeshctl log` escapes it. Without this, a name containing "&",
		// "#" or a space changes the query string instead of being read as a
		// logger name, and the daemon returns data for the wrong logger.
		endpoint = "debug/loggers?name=" + url.QueryEscape(loggerName)
	}
	raw, err := h.fetchFromDaemon(ctx, podName, "kmesh-system", endpoint)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func (h *McpHandler) HandleListDaemonPods(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ns := req.GetString("namespace", "")
	if ns == "" {
		ns = "kmesh-system"
	}
	pods, err := h.cliClient.Kube().CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "app=kmesh",
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list pods: %v", err)), nil
	}

	result := "Kmesh Daemon Pods:\n"
	for _, p := range pods.Items {
		result += fmt.Sprintf("- Pod: %s, Node: %s, Status: %s, IP: %s\n", p.Name, p.Spec.NodeName, p.Status.Phase, p.Status.PodIP)
	}
	return mcp.NewToolResultText(result), nil
}

func (h *McpHandler) HandleGetMeshNamespaces(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	namespaces, err := h.cliClient.Kube().CoreV1().Namespaces().List(ctx, metav1.ListOptions{
		LabelSelector: "istio.io/dataplane-mode=Kmesh",
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list namespaces: %v", err)), nil
	}

	result := "Kmesh-Enabled Namespaces:\n"
	for _, ns := range namespaces.Items {
		result += fmt.Sprintf("- %s\n", ns.Name)
	}
	return mcp.NewToolResultText(result), nil
}

func (h *McpHandler) HandleListWaypoints(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ns := req.GetString("namespace", "")
	allNs := req.GetBool("allNamespaces", false)
	if allNs {
		ns = ""
	}

	gws, err := h.cliClient.GatewayAPI().GatewayV1().Gateways(ns).List(ctx, metav1.ListOptions{
		LabelSelector: "gateway.istio.io/managed=istio.io-mesh-controller",
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list gateways: %v", err)), nil
	}

	var output string
	for _, gw := range gws.Items {
		output += fmt.Sprintf("- Name: %s, Namespace: %s, Class: %s\n", gw.Name, gw.Namespace, gw.Spec.GatewayClassName)
	}
	if output == "" {
		output = "No Waypoint Gateways found."
	}
	return mcp.NewToolResultText(output), nil
}

func (h *McpHandler) HandleGetWaypointStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	name, err := req.RequireString("name")
	if err != nil {
		return mcp.NewToolResultError("name argument is required"), nil
	}
	ns := req.GetString("namespace", "")
	if ns == "" {
		ns = "default"
	}

	gw, err := h.cliClient.GatewayAPI().GatewayV1().Gateways(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Waypoint not found: %v", err)), nil
	}

	statusSummary := fmt.Sprintf("Waypoint: %s/%s\nConditions:\n", ns, name)
	for _, cond := range gw.Status.Conditions {
		statusSummary += fmt.Sprintf("  - Type: %s, Status: %s, Reason: %s\n", cond.Type, cond.Status, cond.Reason)
	}
	return mcp.NewToolResultText(statusSummary), nil
}
