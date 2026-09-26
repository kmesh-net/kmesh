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
	"os"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/mcp"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("kmeshctl/mcp")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Start the Kmesh MCP Server",
		Long:  `Starts the Model Context Protocol (MCP) server for Kmesh, exposing internal daemon data to AI agents.`,
	}

	cmd.AddCommand(serveCmd())
	return cmd
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP SSE transport server",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := utils.CreateKubeClient()
			if err != nil {
				log.Errorf("failed to create kube client: %v", err)
				os.Exit(1)
			}

			// Starts the server and blocks
			mcp.RegisterToolsAndServe(cli)
			return nil
		},
	}
	return cmd
}
