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
	"log"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"kmesh.net/kmesh/pkg/kube"
)

// RegisterToolsAndServe defines the available MCP tools and mounts the HTTP/SSE transport.
func RegisterToolsAndServe(cliClient kube.CLIClient) {
	//Initializing Server
	mcpServer := server.NewMCPServer("Kmesh-MCP-Server", "1.0.0")

	handler := &McpHandler{
		cliClient: cliClient,
	}

	// Define Tools & Bind Handlers
	toolBpfMaps := mcp.NewTool("get_bpf_maps",
		mcp.WithDescription("Retrieves the current eBPF map state from a specific Kmesh daemon pod"),
		mcp.WithString("podName", mcp.Description("Target daemon pod name (auto-discovered if empty)")),
		mcp.WithString("namespace", mcp.Description("Target daemon pod namespace")),
		mcp.WithString("mode", mcp.Required(), mcp.Description("Operating mode (kernel-native or dual-engine)")),
	)
	mcpServer.AddTool(toolBpfMaps, handler.HandleBpfDump)

	toolVersion := mcp.NewTool("get_version",
		mcp.WithDescription("Retrieves daemon version and BPF operating mode"),
		mcp.WithString("podName", mcp.Description("Optional kmesh-daemon pod name")),
	)
	mcpServer.AddTool(toolVersion, handler.HandleGetVersion)

	toolConfigDump := mcp.NewTool("config_dump",
		mcp.WithDescription("Retrieves Istio xDS dynamic listeners, clusters, and routes"),
		mcp.WithString("podName", mcp.Description("Target daemon pod name")),
		mcp.WithString("mode", mcp.Description("Operating mode (kernel-native or dual-engine)")),
	)
	mcpServer.AddTool(toolConfigDump, handler.HandleConfigDump)

	toolListWaypoints := mcp.NewTool("list_waypoints",
		mcp.WithDescription("Lists active Waypoint proxies in the cluster using Gateway API"),
		mcp.WithString("namespace", mcp.Description("Target namespace")),
		mcp.WithBoolean("allNamespaces", mcp.Description("List across all namespaces")),
	)
	mcpServer.AddTool(toolListWaypoints, handler.HandleListWaypoints)

	toolWaypointStatus := mcp.NewTool("get_waypoint_status",
		mcp.WithDescription("Gets health and conditions of a specific Waypoint Gateway"),
		mcp.WithString("name", mcp.Required(), mcp.Description("Name of the waypoint gateway")),
		mcp.WithString("namespace", mcp.Description("Namespace of the waypoint")),
	)
	mcpServer.AddTool(toolWaypointStatus, handler.HandleGetWaypointStatus)

	toolAuthzStatus := mcp.NewTool("get_authz_status",
		mcp.WithDescription("Gets authorization offload status in the kernel"),
		mcp.WithString("podName", mcp.Description("Target daemon pod name")),
	)
	mcpServer.AddTool(toolAuthzStatus, handler.HandleGetAuthzStatus)

	toolDaemonHealth := mcp.NewTool("get_daemon_health",
		mcp.WithDescription("Checks readiness probe of a Kmesh daemon pod"),
		mcp.WithString("podName", mcp.Description("Target daemon pod name")),
	)
	mcpServer.AddTool(toolDaemonHealth, handler.HandleGetDaemonHealth)

	toolLoggerLevels := mcp.NewTool("get_logger_levels",
		mcp.WithDescription("Retrieves log levels of Kmesh internal modules"),
		mcp.WithString("podName", mcp.Description("Target daemon pod name")),
		mcp.WithString("loggerName", mcp.Description("Optional specific logger module name")),
	)
	mcpServer.AddTool(toolLoggerLevels, handler.HandleGetLoggerLevels)

	toolListDaemonPods := mcp.NewTool("list_daemon_pods",
		mcp.WithDescription("Lists all kmesh-daemon pods, their nodes, and IPs"),
		mcp.WithString("namespace", mcp.Description("Namespace where Kmesh is running (default: kmesh-system)")),
	)
	mcpServer.AddTool(toolListDaemonPods, handler.HandleListDaemonPods)

	toolMeshNamespaces := mcp.NewTool("get_mesh_namespaces",
		mcp.WithDescription("Filters namespaces that have istio.io/dataplane-mode=Kmesh label"),
	)
	mcpServer.AddTool(toolMeshNamespaces, handler.HandleGetMeshNamespaces)

	//Transport Layer Setup for remote network connections
	sseServer := server.NewSSEServer(mcpServer)

	log.Println("Kmesh MCP Server running on :8080...")
	if err := sseServer.Start(":8080"); err != nil {
		log.Fatalf("mcp server crashed: %v", err)
	}
}
