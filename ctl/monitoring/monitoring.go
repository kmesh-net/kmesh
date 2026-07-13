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

package monitoring

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	patternAccesslog         = "/accesslog"
	patternMonitoring        = "/monitoring"
	patternWorkloadMetrics   = "/workload_metrics"
	patternConnectionMetrics = "/connection_metrics"
)

// Different types of monitoring
const (
	MONITORING = "monitoring"
	ACCESSLOG  = "accesslog"
	WORKLOAD   = "workload metrics"
	CONNECTION = "connection metrics"
)

var log = logger.NewLoggerScope("kmeshctl/monitoring")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitoring",
		Short: "Control Kmesh's monitoring to be turned on as needed",
		Example: `# Enable/Disable Kmesh's accesslog:
kmeshctl monitoring <kmesh-daemon-pod> --accesslog enable/disable

# Enable/Disable services' metrics and accesslog generated from bpf:
kmeshctl monitoring <kmesh-daemon-pod> --all enable/disable

# Enable/Disable workload granularity metrics:
kmeshctl monitoring <kmesh-daemon-pod> --workloadMetrics enable/disable

# Enable/Disable connection granularity metrics:
kmeshctl monitoring <kmesh-daemon-pod> --connectionMetrics enable/disable

# If you want to change the monitoring functionality of all kmesh daemons in the cluster
# Enable/Disable Kmesh's accesslog in each node:
kmeshctl monitoring --accesslog enable/disable

# Enable/Disable workload granularity metrics in each node:
kmeshctl monitoring --workloadMetrics enable/disable

# Enable/Disable connection granularity metrics in each node:
kmeshctl monitoring --connectionMetrics enable/disable

#Enable/Disable services', workloads' and 'connections' metrics and accesslog generated from bpf in each node:
kmeshctl monitoring --all enable/disable`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return ControlMonitoring(cmd, args)
		},
	}
	cmd.Flags().String("accesslog", "", "Control accesslog enable or disable")
	cmd.Flags().String("all", "", "Control accesslog and services' and workloads' metrics enable or disable together")
	cmd.Flags().String("workloadMetrics", "", "Control workload granularity metrics enable or disable")
	cmd.Flags().String("connectionMetrics", "", "Control connection granularity metrics enable or disable")
	return cmd
}

func ControlMonitoring(cmd *cobra.Command, args []string) error {
	client, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %v", err)
	}
	accesslogFlag, _ := cmd.Flags().GetString("accesslog")
	allFlag, _ := cmd.Flags().GetString("all")
	workloadMetricsFlag, _ := cmd.Flags().GetString("workloadMetrics")
	connectionMetricsFlag, _ := cmd.Flags().GetString("connectionMetrics")
	if accesslogFlag == "" && allFlag == "" && workloadMetricsFlag == "" && connectionMetricsFlag == "" {
		cmd.Println("no parameters. Need --accesslog, --workloadMetrics, --connectionMetrics or --all")
		return nil
	}

	podName, hasKmeshPod := getKmeshDaemonPod(args)
	if hasKmeshPod {
		// Processes triggers for specified kmesh daemon.
		if allFlag != "" {
			if err := SetObservabilityPerKmeshDaemon(client, podName, allFlag, MONITORING, patternMonitoring); err != nil {
				return err
			}
		}
		if accesslogFlag != "" {
			if err := SetObservabilityPerKmeshDaemon(client, podName, accesslogFlag, ACCESSLOG, patternAccesslog); err != nil {
				return err
			}
		}
		if workloadMetricsFlag != "" {
			if err := SetObservabilityPerKmeshDaemon(client, podName, workloadMetricsFlag, WORKLOAD, patternWorkloadMetrics); err != nil {
				return err
			}
		}
		if connectionMetricsFlag != "" {
			if err := SetObservabilityPerKmeshDaemon(client, podName, connectionMetricsFlag, CONNECTION, patternConnectionMetrics); err != nil {
				return err
			}
		}
	} else {
		// Perform operations on all kmesh daemons.
		podList, err := client.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			return fmt.Errorf("failed to get kmesh podList: %v", err)
		}
		for _, pod := range podList.Items {
			if allFlag != "" {
				if err := SetObservabilityPerKmeshDaemon(client, pod.GetName(), allFlag, MONITORING, patternMonitoring); err != nil {
					return err
				}
			}
			if accesslogFlag != "" {
				if err := SetObservabilityPerKmeshDaemon(client, pod.GetName(), accesslogFlag, ACCESSLOG, patternAccesslog); err != nil {
					return err
				}
			}
			if workloadMetricsFlag != "" {
				if err := SetObservabilityPerKmeshDaemon(client, pod.GetName(), workloadMetricsFlag, WORKLOAD, patternWorkloadMetrics); err != nil {
					return err
				}
			}
			if connectionMetricsFlag != "" {
				if err := SetObservabilityPerKmeshDaemon(client, pod.GetName(), connectionMetricsFlag, CONNECTION, patternConnectionMetrics); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func getKmeshDaemonPod(args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	if strings.HasPrefix(args[0], "--") {
		return "", false
	}
	return args[0], true
}

func SetObservabilityPerKmeshDaemon(cli kube.CLIClient, podName, info string, observabilityType string, pattern string) error {
	var status string
	if info == "enable" {
		status = "true"
	} else if info == "disable" {
		status = "false"
	} else {
		return fmt.Errorf("error: argument must be 'enable' or 'disable'")
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	if err := fw.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), pattern, status)
	return SetObservability(url, observabilityType)
}

// SetObservability sends a POST request to the specified URL to set the observability flag.
func SetObservability(url string, observabilityType string) error {
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
		if observabilityType == MONITORING {
			return fmt.Errorf("received status code %d", resp.StatusCode)
		}
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("received status code %d, and error reading response body: %v", resp.StatusCode, readErr)
		}
		bodyString := string(bodyBytes)
		if resp.StatusCode == http.StatusBadRequest && strings.Contains(bodyString, fmt.Sprintf("Kmesh monitoring is disabled, cannot enable %s.", observabilityType)) {
			return fmt.Errorf("failed to enable %s: %v. Need to start Kmesh's Monitoring. Please run `kmeshctl monitoring -h` for more help", observabilityType, bodyString)
		}
		return fmt.Errorf("received status code %d, Response body: %s", resp.StatusCode, bodyString)
	}
	return nil
}
