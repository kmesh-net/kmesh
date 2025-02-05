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

package authz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	patternAuthz = "/authz"
)

var log = logger.NewLoggerScope("kmeshctl/authz")

// NewCmd returns the root authz command with its subcommands.
func NewCmd() *cobra.Command {
	authzCmd := &cobra.Command{
		Use:   "authz",
		Short: "Manage xdp authz eBPF program for Kmesh's authz offloading",
	}

	authzCmd.AddCommand(NewEnableCmd())
	authzCmd.AddCommand(NewDisableCmd())
	authzCmd.AddCommand(NewStatusCmd())

	return authzCmd
}

// NewEnableCmd creates a command to enable authz.
func NewEnableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "enable [podNames...]",
		Short:   "Enable xdp authz eBPF program for Kmesh's authz offloading",
		Example: "kmeshctl authz enable\nkmeshctl authz pod1 pod2 enable",
		Args:    cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			// If no pod names are given, apply to all kmesh daemon pods.
			SetAuthzForPods(args, "true")
			log.Info("Authorization has been enabled.")
		},
	}
	return cmd
}

// NewDisableCmd creates a command to disable authz.
func NewDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "disable [podNames...]",
		Short:   "Disable xdp authz eBPF program for Kmesh's authz offloading",
		Example: "kmeshctl authz disable\nkmeshctl authz pod1 pod2 disable",
		Args:    cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			SetAuthzForPods(args, "false")
			log.Info("Authorization has been disabled.")
		},
	}
	return cmd
}

// NewStatusCmd creates a command to display the current authz status.
func NewStatusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "status [podNames...]",
		Short:   "Display the current authorization status",
		Example: "kmeshctl authz status\nkmeshctl authz status pod1 pod2",
		Args:    cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cli, err := utils.CreateKubeClient()
			if err != nil {
				log.Errorf("failed to create cli client: %v", err)
				os.Exit(1)
			}

			// Determine which pods to query.
			var podNames []string
			if len(args) == 0 {
				podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
				if err != nil {
					log.Errorf("failed to get kmesh podList: %v", err)
					os.Exit(1)
				}
				for _, pod := range podList.Items {
					podNames = append(podNames, pod.GetName())
				}
			} else {
				podNames = args
			}

			// Collect the status for each pod.
			type podStatus struct {
				Pod    string
				Status string
			}
			var statuses []podStatus
			for _, podName := range podNames {
				status, err := fetchAuthzStatus(cli, podName)
				if err != nil {
					log.Errorf("failed to get authz status for pod %s: %v", podName, err)
					continue
				}
				statuses = append(statuses, podStatus{Pod: podName, Status: status})
			}

			// Output the results in a table format.
			var buf bytes.Buffer
			tw := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "POD\tAUTHORIZATION STATUS")
			for _, s := range statuses {
				fmt.Fprintf(tw, "%s\t%s\n", s.Pod, s.Status)
			}
			tw.Flush()
			fmt.Print(buf.String())
		},
	}
	return cmd
}

// SetAuthzForPods applies the authz setting (enable/disable) for the given pod(s).
// If no pod names are specified, it applies the setting to all kmesh daemon pods.
func SetAuthzForPods(podNames []string, info string) {
	cli, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}

	if len(podNames) == 0 {
		// Apply to all kmesh daemon pods.
		podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			log.Errorf("failed to get kmesh podList: %v", err)
			os.Exit(1)
		}
		for _, pod := range podList.Items {
			SetAuthzPerKmeshDaemon(cli, pod.GetName(), info)
		}
	} else {
		// Process for specified pods.
		for _, podName := range podNames {
			SetAuthzPerKmeshDaemon(cli, podName, info)
		}
	}
}

// SetAuthzPerKmeshDaemon sends a POST request to a specific kmesh daemon pod
// to set the authz flag based on the info parameter ("true" or "false").
func SetAuthzPerKmeshDaemon(cli kube.CLIClient, podName, info string) {
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

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternAuthz, info)

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

	if resp.StatusCode != http.StatusOK {
		log.Errorf("Error: received status code %d", resp.StatusCode)
		return
	}
}

// fetchAuthzStatus sends a GET request to a specific kmesh daemon pod
// to retrieve the current authz status and returns it.
func fetchAuthzStatus(cli kube.CLIClient, podName string) (string, error) {
	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return "", fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	if err := fw.Start(); err != nil {
		return "", fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s", fw.Address(), patternAuthz)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to make HTTP request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("received status code %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %v", err)
	}

	status := string(bodyBytes)
	return status, nil
}
