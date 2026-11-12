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
	"fmt"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/mcp"
)

var transport string

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Manage the Kmesh Model Context Protocol (MCP) server",
		Long:  `Manage and run the Model Context Protocol (MCP) server for Kmesh, exposing internal daemon data to AI agents.`,
	}

	cmd.AddCommand(serveCmd())
	return cmd
}

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP server (supports stdio and sse transport)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := utils.CreateKubeClient()
			if err != nil {
				return fmt.Errorf("failed to create kube client: %w", err)
			}

			return mcp.RegisterToolsAndServe(cmd.Context(), cli, transport)
		},
	}

	cmd.Flags().StringVar(&transport, "transport", "stdio", "Transport protocol to use: 'stdio' (default) or 'sse'")
	return cmd
}
