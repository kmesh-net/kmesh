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
	"net/http"
	"net/url"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	istioconstants "istio.io/istio/pkg/config/constants"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/kube"
)

type McpHandler struct {
	cliClient kube.CLIClient
	fetch     func(ctx context.Context, podName, namespace, endpoint string) ([]byte, error)
}

func (h *McpHandler) getDefaultDaemonPod(ctx context.Context, namespace string) (string, error) {
	if namespace == "" {
		namespace = utils.KmeshNamespace
	}
	pods, err := h.cliClient.Kube().CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: utils.KmeshLabel,
	})
	if err != nil {
		return "", fmt.Errorf("failed to list kmesh pods: %v", err)
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no kmesh daemon pods found in namespace %s", namespace)
	}

	for _, pod := range pods.Items {
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Status.Phase != corev1.PodRunning {
			continue
		}
		for _, cond := range pod.Status.Conditions {
			if cond.Type == corev1.PodReady && cond.Status == corev1.ConditionTrue {
				return pod.Name, nil
			}
		}
	}

	return "", fmt.Errorf("found %d kmesh daemon pod(s) in namespace %s, but none are ready", len(pods.Items), namespace)
}

func (h *McpHandler) fetchFromDaemon(ctx context.Context, podName, namespace, endpoint string) ([]byte, error) {
	if h.fetch != nil {
		return h.fetch(ctx, podName, namespace, endpoint)
	}

	if namespace == "" {
		namespace = utils.KmeshNamespace
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

	fw, err := h.cliClient.NewPortForwarder(podName, namespace, "", 0, utils.KmeshAdminPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create port-forward to %s in namespace %s: %w", podName, namespace, err)
	}

	startErrCh := make(chan error, 1)
	go func() {
		startErrCh <- fw.Start()
	}()

	select {
	case <-ctx.Done():
		fw.Close()
		return nil, fmt.Errorf("timed out connecting to daemon pod %s in namespace %s", podName, namespace)
	case err := <-startErrCh:
		if err != nil {
			return nil, fmt.Errorf("failed to start forward to %s in namespace %s: %w", podName, namespace, err)
		}
	}
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

	return readAllLimited(resp.Body, maxDumpBytes)
}

func (h *McpHandler) HandleBpfDump(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")
	mode := req.GetString("mode", "")
	summary := req.GetBool("summary", true)
	filter := req.GetString("filter", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if mode == "" {
		rawVersion, err := h.fetchFromDaemon(ctx, podName, namespace, "version")
		if err == nil {
			var vInfo struct {
				Mode string `json:"mode"`
			}
			if json.Unmarshal(rawVersion, &vInfo) == nil && vInfo.Mode != "" {
				mode = vInfo.Mode
			}
		}
	}

	if mode == "" {
		mode = constants.KernelNativeMode
	}

	if mode != constants.KernelNativeMode && mode != constants.DualEngineMode {
		return mcp.NewToolResultError(fmt.Sprintf("mode must be %q or %q, got %q",
			constants.KernelNativeMode, constants.DualEngineMode, mode)), nil
	}

	endpoint := fmt.Sprintf("debug/config_dump/bpf/%s", mode)
	raw, err := h.fetchFromDaemon(ctx, podName, namespace, endpoint)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch BPF maps: %v", err)), nil
	}

	out, err := formatDump(raw, filter, summary)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to process BPF maps: %v", err)), nil
	}
	return mcp.NewToolResultText(out), nil
}

func (h *McpHandler) HandleGetVersion(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	raw, err := h.fetchFromDaemon(ctx, podName, namespace, "version")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func (h *McpHandler) HandleConfigDump(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")
	mode := req.GetString("mode", "")
	summary := req.GetBool("summary", true)
	filter := req.GetString("filter", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	if mode != "" && mode != constants.KernelNativeMode && mode != constants.DualEngineMode {
		return mcp.NewToolResultError(fmt.Sprintf("mode must be %q or %q, got %q",
			constants.KernelNativeMode, constants.DualEngineMode, mode)), nil
	}

	endpoint := "debug/config_dump"
	if mode != "" {
		endpoint = fmt.Sprintf("debug/config_dump/%s", mode)
	}

	raw, err := h.fetchFromDaemon(ctx, podName, namespace, endpoint)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	out, err := formatDump(raw, filter, summary)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to process config dump: %v", err)), nil
	}
	return mcp.NewToolResultText(out), nil
}

func (h *McpHandler) HandleGetAuthzStatus(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	raw, err := h.fetchFromDaemon(ctx, podName, namespace, "authz")
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func (h *McpHandler) HandleGetDaemonHealth(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	raw, err := h.fetchFromDaemon(ctx, podName, namespace, "debug/ready")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Health check failed: %v", err)), nil
	}
	return mcp.NewToolResultText(fmt.Sprintf("Pod is READY. Response: %s", string(raw))), nil
}

func (h *McpHandler) HandleGetLoggerLevels(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName := req.GetString("podName", "")
	namespace := req.GetString("namespace", "")
	loggerName := req.GetString("loggerName", "")

	if err := validateK8sName("podName", podName); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", namespace); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	endpoint := "debug/loggers"
	if loggerName != "" {
		endpoint = "debug/loggers?name=" + url.QueryEscape(loggerName)
	}
	raw, err := h.fetchFromDaemon(ctx, podName, namespace, endpoint)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	return mcp.NewToolResultText(string(raw)), nil
}

func (h *McpHandler) HandleListDaemonPods(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	ns := req.GetString("namespace", "")
	if ns == "" {
		ns = utils.KmeshNamespace
	}

	if err := validateK8sName("namespace", ns); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	pods, err := h.cliClient.Kube().CoreV1().Pods(ns).List(ctx, metav1.ListOptions{
		LabelSelector: utils.KmeshLabel,
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list pods: %v", err)), nil
	}

	if len(pods.Items) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No Kmesh daemon pods found in namespace %s.", ns)), nil
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

	if len(namespaces.Items) == 0 {
		return mcp.NewToolResultText("No namespaces found with label 'istio.io/dataplane-mode=Kmesh'."), nil
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
	} else if ns == "" {
		ns = "default"
	}

	if ns != "" {
		if err := validateK8sName("namespace", ns); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
	}

	gws, err := h.cliClient.GatewayAPI().GatewayV1().Gateways(ns).List(ctx, metav1.ListOptions{})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to list gateways: %v", err)), nil
	}

	var output string
	for _, gw := range gws.Items {
		if string(gw.Spec.GatewayClassName) != istioconstants.WaypointGatewayClassName {
			continue
		}
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

	if err := validateK8sName("name", name); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	if err := validateK8sName("namespace", ns); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	gw, err := h.cliClient.GatewayAPI().GatewayV1().Gateways(ns).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Waypoint not found: %v", err)), nil
	}

	statusSummary := fmt.Sprintf("Waypoint: %s/%s\nConditions:\n", ns, name)
	if len(gw.Status.Conditions) == 0 {
		statusSummary += "  (no conditions reported yet)\n"
	} else {
		for _, cond := range gw.Status.Conditions {
			statusSummary += fmt.Sprintf("  - Type: %s, Status: %s, Reason: %s\n", cond.Type, cond.Status, cond.Reason)
		}
	}
	return mcp.NewToolResultText(statusSummary), nil
}
