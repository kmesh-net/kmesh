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

package dnsproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
)

const patternDnsproxy = "/dnsproxy"

var log = logger.NewLoggerScope("kmeshctl/dnsproxy")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnsproxy [pod] enable|disable",
		Short: "Enable or disable Kmesh's DNS proxy",
		Example: `# Enable Kmesh's DNS proxy:
kmeshctl dnsproxy <kmesh-daemon-pod> enable

# Disable Kmesh's DNS proxy:
kmeshctl dnsproxy <kmesh-daemon-pod> disable

# Enable/Disable DNS proxy on all kmesh daemons in the cluster:
kmeshctl dnsproxy enable
kmeshctl dnsproxy disable`,
		Args: cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			ControlDnsproxy(cmd, args)
		},
	}
	return cmd
}

func ControlDnsproxy(cmd *cobra.Command, args []string) {
	client, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}

	var podName string
	var enableStr string
	if len(args) == 1 {
		enableStr = args[0]
		podName = ""
	} else {
		podName = args[0]
		enableStr = args[1]
	}

	if enableStr != "enable" && enableStr != "disable" {
		log.Errorf("Error: Argument must be 'enable' or 'disable'")
		os.Exit(1)
	}

	if podName != "" && strings.Contains(podName, "--") {
		log.Errorf("Error: Invalid pod name")
		os.Exit(1)
	}

	if podName != "" {
		SetDnsproxyPerKmeshDaemon(client, podName, enableStr)
		return
	}

	// Apply to all kmesh daemons
	podList, err := client.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
	if err != nil {
		log.Errorf("failed to get kmesh podList: %v", err)
		os.Exit(1)
	}
	for _, pod := range podList.Items {
		SetDnsproxyPerKmeshDaemon(client, pod.GetName(), enableStr)
	}
}

func SetDnsproxyPerKmeshDaemon(cli kube.CLIClient, podName, info string) {
	var status string
	if info == "enable" {
		status = "true"
	} else {
		status = "false"
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

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternDnsproxy, status)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Errorf("failed to make HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("Error: received status code %d", resp.StatusCode)
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Errorf("Error reading response body: %v", readErr)
			return
		}
		log.Errorf("response: %s", string(bodyBytes))
	}
}
