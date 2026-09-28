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

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	patternDnsproxy = "/dnsproxy"
)

var log = logger.NewLoggerScope("kmeshctl/dnsproxy")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnsproxy",
		Short: "Control Kmesh's DNS proxy to be enabled or disabled at runtime",
		Example: `# Enable DNS proxy for a specific kmesh daemon pod:
kmeshctl dnsproxy <kmesh-daemon-pod> enable

# Disable DNS proxy for a specific kmesh daemon pod:
kmeshctl dnsproxy <kmesh-daemon-pod> disable

# Check DNS proxy status for a specific kmesh daemon pod:
kmeshctl dnsproxy <kmesh-daemon-pod> status

# Enable DNS proxy for all kmesh daemon pods:
kmeshctl dnsproxy enable

# Disable DNS proxy for all kmesh daemon pods:
kmeshctl dnsproxy disable

# Check DNS proxy status for all kmesh daemon pods:
kmeshctl dnsproxy status`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return controlDnsproxy(args)
		},
	}
	return cmd
}

func controlDnsproxy(args []string) error {
	client, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %v", err)
	}

	var podName, action string

	if len(args) == 2 {
		// kmeshctl dnsproxy <podName> enable/disable/status
		podName = args[0]
		action = args[1]
	} else {
		// kmeshctl dnsproxy enable/disable/status
		action = args[0]
	}

	if action != "enable" && action != "disable" && action != "status" {
		return fmt.Errorf("invalid action %q: must be 'enable', 'disable', or 'status'", action)
	}

	if podName != "" {
		// Target a specific pod
		return handlePodAction(client, podName, action)
	}

	// Target all kmesh daemon pods
	podList, err := client.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
	if err != nil {
		return fmt.Errorf("failed to get kmesh podList: %v", err)
	}

	var lastErr error
	for _, pod := range podList.Items {
		if err := handlePodAction(client, pod.GetName(), action); err != nil {
			log.Errorf("failed to %s dnsproxy for pod %s: %v", action, pod.GetName(), err)
			lastErr = err
		}
	}
	return lastErr
}

func handlePodAction(cli kube.CLIClient, podName, action string) error {
	if action == "status" {
		return fetchDnsProxyStatus(cli, podName)
	}
	return setDnsProxyPerKmeshDaemon(cli, podName, action)
}

func setDnsProxyPerKmeshDaemon(cli kube.CLIClient, podName, action string) error {
	var status string
	if action == "enable" {
		status = "true"
	} else {
		status = "false"
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	if err := fw.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternDnsproxy, status)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	httpClient := &http.Client{}
	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("received status code %d, failed to read response body: %v", resp.StatusCode, readErr)
		}
		return fmt.Errorf("received status code %d, response: %s", resp.StatusCode, string(bodyBytes))
	}

	fmt.Printf("DNS proxy %sd for pod %s\n", action, podName)
	return nil
}

func fetchDnsProxyStatus(cli kube.CLIClient, podName string) error {
	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	if err := fw.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s", fw.Address(), patternDnsproxy)
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to get DNS proxy status: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	fmt.Printf("Pod: %s\tDNS Proxy: %s\n", podName, string(bodyBytes))
	return nil
}
