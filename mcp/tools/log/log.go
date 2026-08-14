package log

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
)

var logScope = logger.NewLoggerScope("mcp-server/tools/log")

const patternLoggers = "/debug/loggers"

type LoggerInfo struct {
	Name  string `json:"name,omitempty"`
	Level string `json:"level,omitempty"`
}

// Register registers the log related tools to the MCP server
func Register(srv *server.MCPServer) {
	// 1. Tool to GET logs
	getTool := mcp.NewTool("kmesh_log_get",
		mcp.WithDescription("Get the kmesh-daemon's logger levels. Returns a list of loggers if loggerName is empty, or the specific logger level if provided."),
		mcp.WithString("podName", mcp.Description("The Kmesh daemon pod name to target (e.g., kmesh-xxx)"), mcp.Required()),
		mcp.WithString("loggerName", mcp.Description("Optional logger name. If omitted, lists all available loggers.")),
	)
	srv.AddTool(getTool, kmeshLogGetHandler)

	// 2. Tool to SET logs
	setTool := mcp.NewTool("kmesh_log_set",
		mcp.WithDescription("Set the kmesh-daemon's logger level (e.g., debug, info, warn, error)."),
		mcp.WithString("podName", mcp.Description("The Kmesh daemon pod name to target"), mcp.Required()),
		mcp.WithString("loggerName", mcp.Description("The logger name to update (e.g., 'default' or 'bpf')"), mcp.Required()),
		mcp.WithString("loggerLevel", mcp.Description("The new logger level (e.g., debug, info, warn, error)"), mcp.Required()),
	)
	srv.AddTool(setTool, kmeshLogSetHandler)

	logScope.Infof("Registered tools: kmesh_log_get, kmesh_log_set")
}

func kmeshLogGetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName, ok := request.Params.Arguments["podName"].(string)
	if !ok || podName == "" {
		return mcp.NewToolResultError("podName argument is required"), nil
	}

	loggerName, _ := request.Params.Arguments["loggerName"].(string)

	cli, err := utils.CreateKubeClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create kube client: %v", err)), nil
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create port forwarder for pod %s: %v", podName, err)), nil
	}
	if err := fw.Start(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to start port forwarder: %v", err)), nil
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s", fw.Address(), patternLoggers)
	if loggerName != "" {
		url += fmt.Sprintf("?name=%s", loggerName)
		
		// Get specific logger
		var loggerInfo LoggerInfo
		if err := getJSON(url, &loggerInfo); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("failed to get logger level: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Logger Name: %s\nLogger Level: %s", loggerInfo.Name, loggerInfo.Level)), nil
	}

	// Get all loggers
	var loggerNames []string
	if err := getJSON(url, &loggerNames); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to get logger names: %v", err)), nil
	}

	result := "Existing Loggers:\n"
	for _, name := range loggerNames {
		result += fmt.Sprintf("- %s\n", name)
	}
	return mcp.NewToolResultText(result), nil
}

func kmeshLogSetHandler(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	podName, ok := request.Params.Arguments["podName"].(string)
	if !ok || podName == "" {
		return mcp.NewToolResultError("podName argument is required"), nil
	}

	loggerName, ok := request.Params.Arguments["loggerName"].(string)
	if !ok || loggerName == "" {
		return mcp.NewToolResultError("loggerName argument is required"), nil
	}

	loggerLevel, ok := request.Params.Arguments["loggerLevel"].(string)
	if !ok || loggerLevel == "" {
		return mcp.NewToolResultError("loggerLevel argument is required"), nil
	}

	cli, err := utils.CreateKubeClient()
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create kube client: %v", err)), nil
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to create port forwarder for pod %s: %v", podName, err)), nil
	}
	if err := fw.Start(); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to start port forwarder: %v", err)), nil
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s", fw.Address(), patternLoggers)

	loggerInfo := LoggerInfo{
		Name:  loggerName,
		Level: loggerLevel,
	}
	data, err := json.Marshal(loggerInfo)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error marshaling logger info: %v", err)), nil
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("error creating request: %v", err)), nil
	}
	req.Header.Set("Content-Type", "application/json")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to make HTTP request: %v", err)), nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return mcp.NewToolResultError(fmt.Sprintf("error: received status code %d", resp.StatusCode)), nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("failed to read HTTP response body: %v", err)), nil
	}

	return mcp.NewToolResultText(fmt.Sprintf("Success: %s", string(body))), nil
}

func getJSON(url string, val any) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed making GET request(%s): %v", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed reading response body(%s): %v", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received status code %d, Response body: %s", resp.StatusCode, body)
	}

	err = json.Unmarshal(body, val)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response body: %v", err)
	}

	return nil
}
