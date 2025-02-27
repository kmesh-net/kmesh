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

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	patternLoggers = "/debug/loggers"
)

var log = logger.NewLoggerScope("kmeshctl/log")

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

func GetJson(url string, val any) error {
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

func GetLoggerNames(url string) {
	var loggerNames []string
	if err := GetJson(url, &loggerNames); err != nil {
		log.Errorf("failed to get logger names: %v", err)
		return
	}

	fmt.Printf("Existing Loggers:\n")
	for _, logger := range loggerNames {
		fmt.Printf("\t%s\n", logger)
	}
}

func GetLoggerLevel(url string) {
	var loggerInfo LoggerInfo
	if err := GetJson(url, &loggerInfo); err != nil {
		log.Errorf("failed to get logger level: %v", err)
		return
	}

	fmt.Printf("Logger Name: %s\n", loggerInfo.Name)
	fmt.Printf("Logger Level: %s\n", loggerInfo.Level)
}

func SetLoggerLevel(url string, setFlag string) {
	if !strings.Contains(setFlag, ":") {
		log.Errorf("Invalid set flag, which should be loggerName:loggerLevel (e.g. default:debug)")
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
		log.Errorf("Error marshaling logger info: %v", err)
		return
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("failed to make HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("Error: received status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("failed to read HTTP response body: %v", err)
		return
	}
	fmt.Println(string(body))
}

func RunGetOrSetLoggerLevel(cmd *cobra.Command, args []string) {
	podName := args[0]

	cli, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		log.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	if err := fw.Start(); err != nil {
		log.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s", fw.Address(), patternLoggers)

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
