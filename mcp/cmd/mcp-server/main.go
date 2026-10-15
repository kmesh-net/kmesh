package main

import (
	"os"

	mcpserver "kmesh.net/kmesh/mcp/server"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("mcp-server")

func main() {
	srv := mcpserver.NewKmeshMCPServer()

	if err := srv.StartStdio(); err != nil {
		log.Errorf("failed to start MCP server: %v", err)
		os.Exit(1)
	}
}
