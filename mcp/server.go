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

package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"kmesh.net/kmesh/mcp/tools"
)

func main() {
	server := mcp.NewServer(
		&mcp.Implementation{
			Name:    "kmesh-mcp",
			Version: "0.1.0",
		},
		nil,
	)
	mcp.AddTool(
		server,
		&mcp.Tool{
			Name:        "kmesh_version",
			Description: "Get Kmesh build and version information",
		},
		tools.KmeshVersion,
	)

	transport := &mcp.StreamableServerTransport{
		SessionID: "kmesh-mcp",
	}

	if _, err := server.Connect(context.Background(), transport, nil); err != nil {
		log.Fatalf("failed to connect MCP server: %v", err)
	}

	http.Handle("/mcp", transport)

	log.Println("Kmesh MCP server listening on :8080")
	srv := &http.Server{
		Addr:              ":8080",
		Handler:           nil,
		ReadHeaderTimeout: 5 * time.Second,
	}
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("MCP server stopped: %v", err)
	}
}
