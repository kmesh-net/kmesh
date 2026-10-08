package server

import (
	"github.com/mark3labs/mcp-go/server"
)

type KmeshMCPServer struct {
	server *server.MCPServer
}

func NewKmeshMCPServer() *KmeshMCPServer {
	// Initialize the MCP server
	srv := server.NewMCPServer("kmesh-mcp-server", "1.0.0")

	// We'll register tools here later

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
