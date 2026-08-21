package server

import (
	"github.com/mark3labs/mcp-go/server"

	"kmesh.net/kmesh/mcp/tools/daemon"
	"kmesh.net/kmesh/mcp/tools/log"
)

type KmeshMCPServer struct {
	server *server.MCPServer
}

func NewKmeshMCPServer() *KmeshMCPServer {
	// Initialize the MCP server
	srv := server.NewMCPServer("kmesh-mcp-server", "1.0.0")

	// Register tools
	daemon.Register(srv)
	log.Register(srv)

	return &KmeshMCPServer{
		server: srv,
	}
}

func (s *KmeshMCPServer) StartStdio() error {
	return server.ServeStdio(s.server)
}

func (s *KmeshMCPServer) StartSSE(port int) error {
	// Stub for SSE transport
	return nil
}
