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

package version

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/version"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Prints out build version info",
		Example: `# Show version of all kmesh components
kmeshctl version

# Show version info of a specific kmesh daemon
kmeshctl version <kmesh-daemon-pod>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersion(cmd, args)
		},
	}
	return cmd
}

// runVersion output the version info of kmeshctl or kmesh-daemon.
func runVersion(cmd *cobra.Command, args []string) error {
	cli, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create kube client: %w", err)
	}

	if len(args) == 0 {
		v := version.Get()
		if stringMatch(v.GitVersion) {
			cmd.Printf("client version: %s\n", v.GitVersion)
		} else {
			cmd.Printf("client version: %s-%s\n", v.GitVersion, v.GitCommit)
		}

		podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			return fmt.Errorf("failed to get kmesh daemon pods: %w", err)
		}

		daemonVersions := map[string]int{}
		for _, pod := range podList.Items {
			v, err := GetVersion(cli, pod.Name)
			if err != nil {
				return fmt.Errorf("failed to get version for pod %s: %w", pod.Name, err)
			}
			if v.GitVersion != "" {
				if stringMatch(v.GitVersion) {
					daemonVersions[v.GitVersion] = daemonVersions[v.GitVersion] + 1
				} else {
					daemonVersions[v.GitVersion+"-"+v.GitCommit] = daemonVersions[v.GitVersion+"-"+v.GitCommit] + 1
				}
			}
		}
		counts := []string{}
		cmd.Printf("kmesh-daemon version: ")
		for k, v := range daemonVersions {
			counts = append(counts, fmt.Sprintf("%s (%d daemons)", k, v))
		}
		cmd.Printf("%s\n", strings.Join(counts, ", "))
		return nil
	}

	podName := args[0]
	v, err := GetVersion(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to get version for pod %s: %w", podName, err)
	}
	data, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal version info: %w", err)
	}
	cmd.Printf("%s\n", string(data))
	return nil
}

// FetchVersion GETs a daemon /version URL and returns structured version info.
// It is safe for MCP and other callers that need typed data without CLI output.
func FetchVersion(url string) (version.Info, error) {
	resp, err := http.Get(url)
	if err != nil {
		return version.Info{}, fmt.Errorf("failed to make HTTP request(%s): %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return version.Info{}, fmt.Errorf("failed to read HTTP response body(%s): %w", url, err)
	}

	if resp.StatusCode != http.StatusOK {
		return version.Info{}, fmt.Errorf("received status code %d from %s, body: %s", resp.StatusCode, url, body)
	}

	var info version.Info
	if err := json.Unmarshal(body, &info); err != nil {
		return version.Info{}, fmt.Errorf("failed to unmarshal version info: %w", err)
	}
	return info, nil
}

// GetVersion port-forwards to a kmesh-daemon pod and fetches /version.
func GetVersion(client kube.CLIClient, podName string) (version.Info, error) {
	fw, err := utils.CreateKmeshPortForwarder(client, podName)
	if err != nil {
		return version.Info{}, fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	if err := fw.Start(); err != nil {
		return version.Info{}, fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s/version", fw.Address())
	return FetchVersion(url)
}

// match release version vx.y.z-(alpha)
func stringMatch(str string) bool {
	pattern := `^v\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$`
	regex := regexp.MustCompile(pattern)

	return regex.MatchString(str)
}
