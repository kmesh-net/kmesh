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
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
)

const (
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return RunGetOrSetLoggerLevel(cmd, args)
		},
	}
	cmd.Flags().String("set", "", "Set the logger level (e.g., default:debug)")
	return cmd
}

// loggerLevelURL builds the URL that queries a single logger's level.
//
// The name comes straight from the command line, so it has to be escaped. A
// name containing a space builds a malformed request line that the daemon's
// HTTP server rejects before routing, and the caller sees a bare
// "400 Bad Request" instead of the daemon's own "logger <name> does not exist".
// That matters because Kmesh logs tag every line with a subsys field, and those
// values ("cni installer", "cache/v2") read like logger names even though the
// daemon only registers default, fileOnly and bpf. Someone reading logs will
// reasonably try one, and should get told what is actually wrong.
func loggerLevelURL(base, name string) string {
	return base + "?name=" + url.QueryEscape(name)
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

func GetLoggerNames(out io.Writer, url string) error {
	var loggerNames []string
	if err := GetJson(url, &loggerNames); err != nil {
		return fmt.Errorf("failed to get logger names: %v", err)
	}

	fmt.Fprintf(out, "Existing Loggers:\n")
	for _, logger := range loggerNames {
		fmt.Fprintf(out, "\t%s\n", logger)
	}
	return nil
}

func GetLoggerLevel(out io.Writer, url string) error {
	var loggerInfo LoggerInfo
	if err := GetJson(url, &loggerInfo); err != nil {
		return fmt.Errorf("failed to get logger level: %v", err)
	}

	fmt.Fprintf(out, "Logger Name: %s\n", loggerInfo.Name)
	fmt.Fprintf(out, "Logger Level: %s\n", loggerInfo.Level)
	return nil
}

func SetLoggerLevel(out io.Writer, url string, setFlag string) error {
	if !strings.Contains(setFlag, ":") {
		return fmt.Errorf("invalid set flag, which should be loggerName:loggerLevel (e.g. default:debug)")
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
		return fmt.Errorf("error marshaling logger info: %v", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(data))
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("error: received status code %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP response body: %v", err)
	}
	fmt.Fprintln(out, string(body))
	return nil
}

func RunGetOrSetLoggerLevel(cmd *cobra.Command, args []string) error {
	podName := args[0]

	cli, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %v", err)
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	if err := fw.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	defer fw.Close()

	loggersURL := fmt.Sprintf("http://%s%s", fw.Address(), patternLoggers)

	out := cmd.OutOrStdout()
	setFlag, _ := cmd.Flags().GetString("set")
	if setFlag == "" {
		if len(args) >= 2 {
			return GetLoggerLevel(out, loggerLevelURL(loggersURL, args[1]))
		}
		return GetLoggerNames(out, loggersURL)
	}
	return SetLoggerLevel(out, loggersURL, setFlag)
}
