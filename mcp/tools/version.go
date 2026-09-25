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

package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"kmesh.net/kmesh/pkg/version"
)

type VersionInput struct{}

type VersionOutput struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	TreeState string `json:"treeState"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
	Compiler  string `json:"compiler"`
	Platform  string `json:"platform"`
}

func KmeshVersion(
	_ context.Context,
	_ *mcp.CallToolRequest,
	_ VersionInput,
) (*mcp.CallToolResult, VersionOutput, error) {
	v := version.Get()

	return nil, VersionOutput{
		Version:   v.GitVersion,
		Commit:    v.GitCommit,
		TreeState: v.GitTreeState,
		BuildDate: v.BuildDate,
		GoVersion: v.GoVersion,
		Compiler:  v.Compiler,
		Platform:  v.Platform,
	}, nil
}
