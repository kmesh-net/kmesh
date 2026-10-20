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
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"kmesh.net/kmesh/pkg/kube"
)

// RegisterToolsAndServe defines the available MCP tools and mounts the specified transport (stdio or sse).
func RegisterToolsAndServe(ctx context.Context, cliClient kube.CLIClient, transport string) error {
	mcpServer := server.NewMCPServer("Kmesh-MCP-Server", "1.0.0")

	handler := &McpHandler{
		cliClient: cliClient,
	}

	toolBpfMaps := mcp.NewTool("get_bpf_maps",
		mcp.WithDescription("Retrieves the current eBPF map state from a specific Kmesh daemon pod. Use list_daemon_pods to discover pod names. Returns a compact summary by default; use filter to fetch full details of specific entries."),
		mcp.WithString("podName", mcp.Description("Target daemon pod name (auto-discovered if empty)")),
		mcp.WithString("namespace", mcp.Description("Target daemon pod namespace (default: kmesh-system)")),
		mcp.WithString("mode", mcp.Description("Operating mode (kernel-native or dual-engine, auto-detected if empty)")),
		mcp.WithBoolean("summary", mcp.Description("Return counts and compact identities instead of the full dump (default: true)")),
		mcp.WithString("filter", mcp.Description("Case-insensitive substring matched against entry name/IP/UID; matching entries are returned in full")),
	)
	mcpServer.AddTool(toolBpfMaps, handler.HandleBpfDump)

	toolVersion := mcp.NewTool("get_version",
		mcp.WithDescription("Retrieves daemon version and BPF operating mode as plain text/JSON. Use list_daemon_pods to discover pod names."),
		mcp.WithString("podName", mcp.Description("Optional kmesh-daemon pod name (auto-discovered if empty)")),
		mcp.WithString("namespace", mcp.Description("Target daemon pod namespace (default: kmesh-system)")),
	)
	mcpServer.AddTool(toolVersion, handler.HandleGetVersion)

	toolConfigDump := mcp.NewTool("config_dump",
		mcp.WithDescription("Retrieves Istio xDS dynamic listeners, clusters, and routes from a Kmesh daemon pod. Use list_daemon_pods to discover pod names. Returns a compact summary by default; use filter to fetch full details of specific resources."),
		mcp.WithString("podName", mcp.Description("Target daemon pod name (auto-discovered if empty)")),
		mcp.WithString("namespace", mcp.Description("Target daemon pod namespace (default: kmesh-system)")),
		mcp.WithString("mode", mcp.Description("Operating mode (kernel-native or dual-engine)")),
		mcp.WithBoolean("summary", mcp.Description("Return counts and compact identities instead of the full dump (default: true)")),
		mcp.WithString("filter", mcp.Description("Case-insensitive substring matched against resource name/IP/UID; matching resources are returned in full")),
	)
	mcpServer.AddTool(toolConfigDump, handler.HandleConfigDump)

	toolListWaypoints := mcp.NewTool("list_waypoints",
		mcp.WithDescription("Lists active Waypoint proxies in the cluster using Gateway API. Use get_waypoint_status to inspect a specific waypoint."),
		mcp.WithString("namespace", mcp.Description("Target namespace (default: default)")),
		mcp.WithBoolean("allNamespaces", mcp.Description("List across all namespaces")),
	)
	mcpServer.AddTool(toolListWaypoints, handler.HandleListWaypoints)

	toolWaypointStatus := mcp.NewTool("get_waypoint_status",
		mcp.WithDescription("Gets health conditions and readiness of a specific Waypoint Gateway. Use list_waypoints to discover waypoint names."),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of the waypoint gateway")),
		mcp.WithString("namespace", mcp.Description("Namespace of the waypoint (default: default)")),
	)
	mcpServer.AddTool(toolWaypointStatus, handler.HandleGetWaypointStatus)

	toolAuthzStatus := mcp.NewTool("get_authz_status",
		mcp.WithDescription("Gets authorization offload status in the kernel from a specific Kmesh daemon pod. Use list_daemon_pods to discover pod names."),
		mcp.WithString("podName", mcp.Description("Target daemon pod name (auto-discovered if empty)")),
		mcp.WithString("namespace", mcp.Description("Target daemon pod namespace (default: kmesh-system)")),
	)
	mcpServer.AddTool(toolAuthzStatus, handler.HandleGetAuthzStatus)

	toolDaemonHealth := mcp.NewTool("get_daemon_health",
		mcp.WithDescription("Checks readiness probe (/debug/ready) of a Kmesh daemon pod as plain text. Use list_daemon_pods to discover pod names."),
		mcp.WithString("podName", mcp.Description("Target daemon pod name (auto-discovered if empty)")),
		mcp.WithString("namespace", mcp.Description("Target daemon pod namespace (default: kmesh-system)")),
	)
	mcpServer.AddTool(toolDaemonHealth, handler.HandleGetDaemonHealth)

	toolLoggerLevels := mcp.NewTool("get_logger_levels",
		mcp.WithDescription("Retrieves log levels of Kmesh internal modules from a specific daemon pod. Use list_daemon_pods to discover pod names."),
		mcp.WithString("podName", mcp.Description("Target daemon pod name (auto-discovered if empty)")),
		mcp.WithString("namespace", mcp.Description("Target daemon pod namespace (default: kmesh-system)")),
		mcp.WithString("loggerName", mcp.Description("Optional specific logger module name")),
	)
	mcpServer.AddTool(toolLoggerLevels, handler.HandleGetLoggerLevels)

	toolListDaemonPods := mcp.NewTool("list_daemon_pods",
		mcp.WithDescription("Lists all kmesh-daemon pods, their node names, status, and IPs. Use this first to discover active daemon pods for pod-specific tools."),
		mcp.WithString("namespace", mcp.Description("Namespace where Kmesh is running (default: kmesh-system)")),
	)
	mcpServer.AddTool(toolListDaemonPods, handler.HandleListDaemonPods)

	toolMeshNamespaces := mcp.NewTool("get_mesh_namespaces",
		mcp.WithDescription("Filters and lists Kubernetes namespaces that have the istio.io/dataplane-mode=Kmesh label enrolled in the service mesh."),
	)
	mcpServer.AddTool(toolMeshNamespaces, handler.HandleGetMeshNamespaces)

	switch transport {
	case "sse":
		sseServer := server.NewSSEServer(mcpServer)
		addr := "localhost:8080"
		log.Printf("Kmesh MCP Server running on SSE at %s...", addr)

		errChan := make(chan error, 1)
		go func() {
			if err := sseServer.Start(addr); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errChan <- err
			}
			close(errChan)
		}()

		select {
		case <-ctx.Done():
			log.Println("Shutting down Kmesh MCP Server gracefully...")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return sseServer.Shutdown(shutdownCtx)
		case err := <-errChan:
			if err != nil {
				return fmt.Errorf("mcp server error: %w", err)
			}
			return nil
		}

	case "stdio":
		log.Println("Starting Kmesh MCP Server on Stdio transport...")
		stdioServer := server.NewStdioServer(mcpServer)
		return stdioServer.Listen(ctx, os.Stdin, os.Stdout)

	default:
		return fmt.Errorf("invalid transport %q: must be %q or %q", transport, "stdio", "sse")
	}
}
