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

const (
	patternDNSProxy = "/dnsproxy"
)

var log = logger.NewLoggerScope("kmeshctl/dnsproxy")

// NewCmd returns a new cobra command for controlling DNS proxy
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnsproxy",
		Short: "Control Kmesh's DNS proxy feature",
		Long: `Inspect and manage Kmesh's DNS proxy feature.

DNS proxy allows Kmesh daemon to serve DNS requests for kmesh-managed pods,
enabling service discovery through DNS resolution.

This command can be used to check the current DNS proxy status. Note that
runtime toggling of DNS proxy is not supported - to enable or disable DNS
proxy, restart the Kmesh daemon with the --enable-dns-proxy flag.`,
		Example: `# Get DNS proxy status for a specific kmesh daemon pod:
kmeshctl dnsproxy <kmesh-daemon-pod> status

# Get DNS proxy status for all kmesh daemons:
kmeshctl dnsproxy status

# Check if DNS proxy can be enabled (will provide restart guidance):
kmeshctl dnsproxy <kmesh-daemon-pod> enable

# Check if DNS proxy can be disabled (will provide restart guidance):
kmeshctl dnsproxy disable`,
		Args: cobra.RangeArgs(1, 2),
		Run: func(cmd *cobra.Command, args []string) {
			controlDNSProxy(cmd, args)
		},
	}
	return cmd
}

func controlDNSProxy(cmd *cobra.Command, args []string) {
	client, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}

	var action string
	var podName string
	var hasKmeshPod bool

	// Parse arguments: either "action" or "podName action"
	if len(args) == 1 {
		action = args[0]
		hasKmeshPod = false
	} else {
		podName = args[0]
		action = args[1]
		hasKmeshPod = !strings.HasPrefix(podName, "-")
	}

	// Validate action
	if action != "enable" && action != "disable" && action != "status" {
		log.Errorf("Error: action must be 'enable', 'disable', or 'status', got '%s'", action)
		os.Exit(1)
	}

	if hasKmeshPod {
		// Operate on specific kmesh daemon pod
		setDNSProxyPerKmeshDaemon(client, podName, action)
	} else {
		// Operate on all kmesh daemon pods
		podList, err := client.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			log.Errorf("failed to get kmesh podList: %v", err)
			os.Exit(1)
		}
		if len(podList.Items) == 0 {
			log.Errorf("no kmesh daemon pods found in namespace %s", utils.KmeshNamespace)
			os.Exit(1)
		}
		for _, pod := range podList.Items {
			setDNSProxyPerKmeshDaemon(client, pod.GetName(), action)
		}
	}
}

func setDNSProxyPerKmeshDaemon(cli kube.CLIClient, podName, action string) {
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

	if action == "status" {
		getDNSProxyStatus(fw, podName)
		return
	}

	var status string
	if action == "enable" {
		status = "true"
	} else {
		status = "false"
	}

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternDNSProxy, status)

	req, err := http.NewRequest(http.MethodPost, url, nil)
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

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorf("failed to %s DNS proxy for pod %s: %s", action, podName, string(bodyBytes))
		return
	}

	var pastTense string
	if action == "enable" {
		pastTense = "enabled"
	} else {
		pastTense = "disabled"
	}
	log.Infof("successfully %s DNS proxy for pod %s", pastTense, podName)
}

func getDNSProxyStatus(fw kube.PortForwarder, podName string) {
	url := fmt.Sprintf("http://%s%s", fw.Address(), patternDNSProxy)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("failed to make HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("Error reading response body: %v", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Errorf("failed to get DNS proxy status for pod %s: %s", podName, string(bodyBytes))
		return
	}

	fmt.Printf("Pod %s: %s\n", podName, string(bodyBytes))
}
