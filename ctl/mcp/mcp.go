package mcp

import (
	"github.com/spf13/cobra"
	mcpserver "kmesh.net/kmesh/mcp/server"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("kmeshctl/mcp")

func NewCmd() *cobra.Command {
	mcpCmd := &cobra.Command{
		Use:   "mcp",
		Short: "Manage Kmesh Model Context Protocol (MCP) integrations",
	}

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Kmesh MCP server",
		Run: func(cmd *cobra.Command, args []string) {
			srv := mcpserver.NewKmeshMCPServer()
			if err := srv.StartStdio(); err != nil {
				log.Errorf("failed to start MCP server: %v", err)
			}
		},
	}

	mcpCmd.AddCommand(serveCmd)
	return mcpCmd
}
