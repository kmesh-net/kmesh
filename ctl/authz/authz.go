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
		Example: "kmeshctl authz enable\nkmeshctl authz enable pod1 pod2",
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			// If no pod names are given, apply to all kmesh daemon pods.
			if err := SetAuthzForPods(args, "true"); err != nil {
				return err
			}
			cmd.Println("Authorization has been enabled.")
			return nil
		},
	}
	return cmd
}

// NewDisableCmd creates a command to disable authz.
func NewDisableCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "disable [podNames...]",
		Short:   "Disable xdp authz eBPF program for Kmesh's authz offloading",
		Example: "kmeshctl authz disable\nkmeshctl authz disable pod1 pod2",
		Args:    cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := SetAuthzForPods(args, "false"); err != nil {
				return err
			}
			cmd.Println("Authorization has been disabled.")
			return nil
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
		RunE: func(cmd *cobra.Command, args []string) error {
			cli, err := utils.CreateKubeClient()
			if err != nil {
				return fmt.Errorf("failed to create cli client: %v", err)
			}

			// Determine which pods to query.
			var podNames []string
			if len(args) == 0 {
				podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
				if err != nil {
					return fmt.Errorf("failed to get kmesh podList: %v", err)
				}
				for _, pod := range podList.Items {
					podNames = append(podNames, pod.GetName())
				}
			} else {
				podNames = args
			}

			// Prepare a slice of podStatuses. We can pre-allocate since we know how many pods we'll check.
			type podStatus struct {
				Pod    string
				Status string
			}
			statuses := make([]podStatus, 0, len(podNames))

			// Collect the status for each pod.
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
			cmd.Print(buf.String())
			return nil
		},
	}
	return cmd
}

// SetAuthzForPods applies the authz setting (enable/disable) for the given pod(s).
// If no pod names are specified, it applies the setting to all kmesh daemon pods.
func SetAuthzForPods(podNames []string, info string) error {
	cli, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %v", err)
	}

	if len(podNames) == 0 {
		// Apply to all kmesh daemon pods.
		podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			return fmt.Errorf("failed to get kmesh podList: %v", err)
		}
		for _, pod := range podList.Items {
			if err := SetAuthzPerKmeshDaemon(cli, pod.GetName(), info); err != nil {
				return err
			}
		}
	} else {
		// Process for specified pods.
		for _, podName := range podNames {
			if err := SetAuthzPerKmeshDaemon(cli, podName, info); err != nil {
				return err
			}
		}
	}
	return nil
}

// SetAuthzPerKmeshDaemon sends a POST request to a specific kmesh daemon pod
// to set the authz flag based on the info parameter ("true" or "false").
func SetAuthzPerKmeshDaemon(cli kube.CLIClient, podName, info string) error {
	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	if err := fw.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternAuthz, info)
	return SetAuthz(url)
}

// SetAuthz sends a POST request to the specified URL to set the authz flag.
func SetAuthz(url string) error {
	req, err := http.NewRequest(http.MethodPost, url, nil)
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
		return fmt.Errorf("received status code %d", resp.StatusCode)
	}
	return nil
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
	return GetAuthzStatus(url)
}

// GetAuthzStatus sends a GET request to the specified URL to retrieve the current authz status.
func GetAuthzStatus(url string) (string, error) {
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

	return string(bodyBytes), nil
}
