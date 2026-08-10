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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
)

const (
	patternAuthz = "/authz"
)

// PodAuthzStatus is the structured authz status for one daemon pod.
type PodAuthzStatus struct {
	Pod     string `json:"pod"`
	Enabled bool   `json:"enabled"`
}

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
			if err := SetAuthzForPods(args, "true"); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Authorization has been enabled.")
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
			fmt.Fprintln(cmd.OutOrStdout(), "Authorization has been disabled.")
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
				return fmt.Errorf("failed to create cli client: %w", err)
			}

			statuses, err := ListAuthzStatus(cli, args)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "POD\tAUTHORIZATION STATUS")
			for _, s := range statuses {
				status := "disabled"
				if s.Enabled {
					status = "enabled"
				}
				fmt.Fprintf(tw, "%s\t%s\n", s.Pod, status)
			}
			return tw.Flush()
		},
	}
	return cmd
}

// ListAuthzStatus returns authz status for the given pods, or all daemon pods if podNames is empty.
func ListAuthzStatus(cli kube.CLIClient, podNames []string) ([]PodAuthzStatus, error) {
	if len(podNames) == 0 {
		podList, err := utils.ListDaemonPods(context.TODO(), cli, "")
		if err != nil {
			return nil, err
		}
		for _, pod := range podList.Items {
			podNames = append(podNames, pod.GetName())
		}
	}

	statuses := make([]PodAuthzStatus, 0, len(podNames))
	for _, podName := range podNames {
		status, err := GetAuthzStatus(cli, podName)
		if err != nil {
			return nil, fmt.Errorf("failed to get authz status for pod %s: %w", podName, err)
		}
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// SetAuthzForPods applies the authz setting (enable/disable) for the given pod(s).
// If no pod names are specified, it applies the setting to all kmesh daemon pods.
func SetAuthzForPods(podNames []string, info string) error {
	cli, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %w", err)
	}

	if len(podNames) == 0 {
		podList, err := utils.ListDaemonPods(context.TODO(), cli, "")
		if err != nil {
			return err
		}
		for _, pod := range podList.Items {
			if err := SetAuthzPerKmeshDaemon(cli, pod.GetName(), info); err != nil {
				return err
			}
		}
		return nil
	}

	for _, podName := range podNames {
		if err := SetAuthzPerKmeshDaemon(cli, podName, info); err != nil {
			return err
		}
	}
	return nil
}

// SetAuthzPerKmeshDaemon sends a POST request to a specific kmesh daemon pod
// to set the authz flag based on the info parameter ("true" or "false").
func SetAuthzPerKmeshDaemon(cli kube.CLIClient, podName, info string) error {
	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	if err := fw.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternAuthz, info)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("received status code %d, body: %s", resp.StatusCode, body)
	}
	return nil
}

// FetchAuthzStatus GETs /authz and returns structured status.
func FetchAuthzStatus(url string) (enabled bool, err error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return false, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("failed to make HTTP request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("received status code %d, body: %s", resp.StatusCode, bodyBytes)
	}

	var status struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(bodyBytes, &status); err != nil {
		return false, fmt.Errorf("failed to unmarshal authz status: %w", err)
	}
	return status.Enabled, nil
}

// GetAuthzStatus port-forwards to a daemon pod and fetches authz status.
func GetAuthzStatus(cli kube.CLIClient, podName string) (PodAuthzStatus, error) {
	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return PodAuthzStatus{}, fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	if err := fw.Start(); err != nil {
		return PodAuthzStatus{}, fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s", fw.Address(), patternAuthz)
	enabled, err := FetchAuthzStatus(url)
	if err != nil {
		return PodAuthzStatus{}, err
	}
	return PodAuthzStatus{Pod: podName, Enabled: enabled}, nil
}
