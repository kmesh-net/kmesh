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

package logs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"istio.io/istio/pkg/kube"
)

const (
	KmeshNamespace = "kmesh-system"
	KmeshAdminPort = 15200

	patternLoggers = "/debug/loggers"
)

type LoggerInfo struct {
	Name  string `json:"name,omitempty"`
	Level string `json:"level,omitempty"`
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "log",
		Short: "Get or set kmesh-daemon's logger level",
		Example: `# Set default logger's level as "debug":
kmeshctl log <kmesh-daemon-pod> --set default:debug

# Get all loggers' name
kmeshctl log <kmesh-daemon-pod>
	  
# Get default logger's level:
kmeshctl log <kmesh-daemon-pod> default`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			RunGetOrSetLoggerLevel(cmd, args)
		},
	}
	cmd.Flags().String("set", "", "Set the logger level (e.g., default:debug)")
	return cmd
}

func GetJson(url string, val any) {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error making GET request(%s): %v\n", url, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body(%s): %v\n", url, err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: received status code %d\n", resp.StatusCode)
		fmt.Printf("Response body: %s\n", body)
		return
	}

	err = json.Unmarshal(body, val)
	if err != nil {
		fmt.Printf("Error unmarshaling response body: %v\n", err)
		return
	}
}

func GetLoggerNames(url string) {
	var loggerNames []string
	GetJson(url, &loggerNames)
	fmt.Printf("Existing Loggers:\n")
	for _, logger := range loggerNames {
		fmt.Printf("\t%s\n", logger)
	}
}

func GetLoggerLevel(url string) {
	var loggerInfo LoggerInfo
	GetJson(url, &loggerInfo)

	fmt.Printf("Logger Name: %s\n", loggerInfo.Name)
	fmt.Printf("Logger Level: %s\n", loggerInfo.Level)
}

func SetLoggerLevel(url string, setFlag string) {
	if !strings.Contains(setFlag, ":") {
		fmt.Println("Invalid set flag, which should be loggerName:loggerLevel (e.g. default:debug)")
		os.Exit(1)
	}
	splits := strings.Split(setFlag, ":")
	loggerName := splits[0]
	loggerLevel := splits[1]

	loggerInfo := LoggerInfo{
		Name:  loggerName,
		Level: loggerLevel,
	}
	data, err := json.Marshal(loggerInfo)
	if err != nil {
		fmt.Printf("Error marshaling logger info: %v\n", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		fmt.Printf("Error creating request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Error making request: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Printf("Error: received status code %d\n", resp.StatusCode)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return
	}
	fmt.Println(string(body))
}

func RunGetOrSetLoggerLevel(cmd *cobra.Command, args []string) {
	rc, err := kube.DefaultRestConfig("", "")
	if err != nil {
		fmt.Printf("failed to get rest.Config for given kube config file and context: %v", err)
		os.Exit(1)
	}

	cli, err := kube.NewCLIClient(kube.NewClientConfigForRestConfig(rc))
	if err != nil {
		fmt.Printf("failed to create kube client: %v", err)
		os.Exit(1)
	}

	podName := args[0]

	fw, err := cli.NewPortForwarder(podName, KmeshNamespace, "", 0, KmeshAdminPort)
	if err != nil {
		fmt.Printf("failed to create port forwarder: %v", err)
		os.Exit(1)
	}
	if err := fw.Start(); err != nil {
		fmt.Printf("failed to start port forwarder: %v", err)
		os.Exit(1)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s/%s", fw.Address(), patternLoggers)

	setFlag, _ := cmd.Flags().GetString("set")
	if setFlag == "" {
		if len(args) >= 2 {
			url += fmt.Sprintf("?name=%s", args[1])
			GetLoggerLevel(url)
		} else {
			GetLoggerNames(url)
		}
	} else {
		SetLoggerLevel(url, setFlag)
	}
}
