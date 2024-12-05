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
	"bytes"
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
	patternAccesslog       = "/accesslog"
	patternMonitoring      = "/monitoring"
	patternWorkloadMetrics = "/workloadMetrics"
)

var log = logger.NewLoggerScope("kmeshctl/monitoring")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "monitoring",
		Short: "Control Kmesh's monitoring to be turned on as needed",
		Example: `# Enable/Disable Kmesh's accesslog:
kmeshctl monitoring <kmesh-daemon-pod> --accesslog enable/disable

# Enable/Disable Kmesh's metrics and accesslog:
kmeshctl monitoring <kmesh-daemon-pod> --all enable/disable

# Enable/Disable Kmesh's workload metrics:
kmeshctl monitoring <kmesh-daemon-pod> --workloadMetrics enable/disable

# If you want to change the monitoring functionality of all kmesh daemons in the cluster
kmeshctl monitoring --accesslog enable/disable
kmeshctl monitoring --workloadMetrics enable/disable
kmeshctl monitoring --all enable/disable`,
		Args: cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ControlMonitoring(cmd, args)
		},
	}
	cmd.Flags().String("accesslog", "", "Control accesslog enable or disable")
	cmd.Flags().String("all", "", "Control accesslog and metrics enable or disable together")
	cmd.Flags().String("workloadMetrics", "", "Control Metrics for workload enable or disable")
	return cmd
}

func ControlMonitoring(cmd *cobra.Command, args []string) {
	client, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}
	accesslogFlag, _ := cmd.Flags().GetString("accesslog")
	allFlag, _ := cmd.Flags().GetString("all")
	workloadMetricsFlag, _ := cmd.Flags().GetString("workloadMetrics")
	if accesslogFlag == "" && allFlag == "" && workloadMetricsFlag == "" {
		log.Print("no parameters. Need --accesslog or --all")
		return
	}

	podName, hasKmeshPod := getKmeshDaemonPod(args)
	if hasKmeshPod {
		// Processes triggers for specified kmesh daemon.
		if allFlag != "" {
			SetMonitoringPerKmeshDaemon(client, podName, allFlag)
		}
		if accesslogFlag != "" {
			SetAccesslogPerKmeshDaemon(client, podName, accesslogFlag)
		}
		if workloadMetricsFlag != "" {
			SetWorkloadMetricsPerKmeshDaemon(client, podName, workloadMetricsFlag)
		}
	} else {
		// Perform operations on all kmesh daemons.
		podList, err := client.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			log.Errorf("failed to get kmesh podList: %v", err)
			os.Exit(1)
		}
		for _, pod := range podList.Items {
			if allFlag != "" {
				SetMonitoringPerKmeshDaemon(client, pod.GetName(), allFlag)
			}
			if accesslogFlag != "" {
				SetAccesslogPerKmeshDaemon(client, pod.GetName(), accesslogFlag)
			}
			if workloadMetricsFlag != "" {
				SetWorkloadMetricsPerKmeshDaemon(client, pod.GetName(), workloadMetricsFlag)
			}
		}
	}
}

func getKmeshDaemonPod(args []string) (string, bool) {
	if len(args) == 0 {
		return "", false
	}
	if strings.Contains(args[0], "--") {
		return "", false
	}
	return args[0], true
}

func SetAccesslogPerKmeshDaemon(cli kube.CLIClient, podName, info string) {
	var accesslogInfo string
	if info == "enable" {
		accesslogInfo = "true"
	} else if info == "disable" {
		accesslogInfo = "false"
	} else {
		log.Errorf("Error: Argument must be 'enable' or 'disable'")
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

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternAccesslog, accesslogInfo)

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
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Errorf("Error reading response body: %v", readErr)
			return
		}
		bodyString := string(bodyBytes)
		if resp.StatusCode == http.StatusBadRequest && bytes.Contains(bodyBytes, []byte("Kmesh monitoring is disable, cannot enable accesslog")) {
			log.Errorf("failed to enable accesslog: %v. Need to start Kmesh's Monitoring. Please run `kmeshctl monitoring -h` for more help.", bodyString)
			return
		}
		log.Errorf("Error: received status code %d", resp.StatusCode)
		return
	}
}

func SetMonitoringPerKmeshDaemon(cli kube.CLIClient, podName, info string) {
	var monitoringInfo string
	if info == "enable" {
		monitoringInfo = "true"
	} else if info == "disable" {
		monitoringInfo = "false"
	} else {
		log.Errorf("Error: Argument must be 'enable' or 'disable'")
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

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternMonitoring, monitoringInfo)

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

func SetWorkloadMetricsPerKmeshDaemon(cli kube.CLIClient, podName, workloadMetricsInfo string) {
	var info string
	if workloadMetricsInfo == "enable" {
		info = "true"
	} else if workloadMetricsInfo == "disable" {
		info = "false"
	} else {
		log.Errorf("Error: Argument must be 'enable' or 'disable'")
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

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternWorkloadMetrics, info)

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
		bodyBytes, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			log.Errorf("Error reading response body: %v", readErr)
			return
		}
		bodyString := string(bodyBytes)
		if resp.StatusCode == http.StatusBadRequest && bytes.Contains(bodyBytes, []byte("Kmesh monitoring is disable, cannot enable accesslog")) {
			log.Errorf("failed to enable workload metrics: %v. Need to start Kmesh's Monitoring. Please run `kmeshctl monitoring -h` for more help.", bodyString)
			return
		}
		log.Errorf("Error: received status code %d", resp.StatusCode)
		return
	}
}
