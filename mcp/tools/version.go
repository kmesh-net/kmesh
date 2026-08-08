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
