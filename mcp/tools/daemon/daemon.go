package daemon

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("mcp-server/tools/daemon")

// Register registers the daemon related tools to the MCP server
func Register(srv *server.MCPServer) {
	// Define the get_kmesh_daemon_pods tool
	tool := mcp.NewTool("get_kmesh_daemon_pods",
		mcp.WithDescription("Retrieves a list of all currently running Kmesh daemon pods in the Kubernetes cluster. This is essential for determining which pod to target for subsequent log/dump tools."),
	)

	// Add tool to the server
	srv.AddTool(tool, getKmeshDaemonPodsHandler)
	log.Infof("Registered tool: get_kmesh_daemon_pods")
}

func getKmeshDaemonPodsHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// Create Kubernetes client
	cli, err := utils.CreateKubeClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to create Kubernetes client: %v", err)), nil
	}

	// Fetch Kmesh daemon pods
	podList, err := cli.PodsForSelector(ctx, utils.KmeshNamespace, utils.KmeshLabel)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Failed to get kmesh pods: %v", err)), nil
	}

	if len(podList.Items) == 0 {
		return mcp.NewToolResultText(fmt.Sprintf("No Kmesh daemon pods found in namespace '%s' with label '%s'.", utils.KmeshNamespace, utils.KmeshLabel)), nil
	}

	// Format output
	var result string
	result += "Kmesh Daemon Pods:\n"
	for _, pod := range podList.Items {
		result += fmt.Sprintf("- Name: %s (Node: %s, Status: %s, IP: %s)\n",
			pod.Name,
			pod.Spec.NodeName,
			pod.Status.Phase,
			pod.Status.PodIP,
		)
	}

	return mcp.NewToolResultText(result), nil
}
