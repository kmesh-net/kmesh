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

package nodesummary

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var log = logger.NewLoggerScope("kmeshctl/node-summary")

type workloadDump struct {
	Workloads []interface{} `json:"workloads"`
	Services  []interface{} `json:"services"`
	Policies  []interface{} `json:"policies"`
}

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "node-summary",
		Short: "Display a cluster-wide summary of all Kmesh daemons and resource counts",
		Example: `  # Show summary of all nodes:
  kmeshctl node-summary`,
		Args: cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := RunNodeSummary(cmd); err != nil {
				log.Errorf("Error: %v", err)
				os.Exit(1)
			}
		},
	}
	return cmd
}

func RunNodeSummary(cmd *cobra.Command) error {
	cli, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %v", err)
	}

	podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
	if err != nil {
		return fmt.Errorf("failed to list kmesh daemon pods: %v", err)
	}

	if len(podList.Items) == 0 {
		fmt.Println("No Kmesh daemon pods found in namespace kmesh-system.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "\nNODE_NAME\tKMESH_POD\tMODE\tVERSION\tLISTENERS/WORKLOADS\tCLUSTERS/SERVICES\tROUTES/POLICIES")

	for _, pod := range podList.Items {
		podName := pod.GetName()
		nodeName := pod.Spec.NodeName
		if nodeName == "" {
			nodeName = "-"
		}

		fw, err := utils.CreateKmeshPortForwarder(cli, podName)
		if err != nil {
			fmt.Fprintf(w, "%s\t%s\tError\t-\t-\t-\t-\n", nodeName, podName)
			continue
		}
		if err := fw.Start(); err != nil {
			fmt.Fprintf(w, "%s\t%s\tOffline\t-\t-\t-\t-\n", nodeName, podName)
			fw.Close()
			continue
		}

		// 1. Fetch version using the same struct as kmeshctl version
		vStr := "-"
		respV, err := http.Get(fmt.Sprintf("http://%s/version", fw.Address()))
		if err == nil && respV.StatusCode == http.StatusOK {
			bodyV, _ := io.ReadAll(respV.Body)
			respV.Body.Close()
			var v version.Info
			if json.Unmarshal(bodyV, &v) == nil && v.GitVersion != "" {
				vStr = v.GitVersion
			}
		} else if respV != nil {
			respV.Body.Close()
		}

		// 2. Fetch mode and counts by trying kernel-native first
		mode := "unknown"
		listenersCount, clustersCount, routesCount := 0, 0, 0

		respKN, err := http.Get(fmt.Sprintf("http://%s/debug/config_dump/kernel-native", fw.Address()))
		if err == nil && respKN.StatusCode == http.StatusOK {
			mode = "kernel-native"
			bodyKN, _ := io.ReadAll(respKN.Body)
			respKN.Body.Close()
			configDump := &adminv2.ConfigDump{}
			if protojson.Unmarshal(bodyKN, configDump) == nil {
				static, dynamic := configDump.GetStaticResources(), configDump.GetDynamicResources()
				if static != nil {
					listenersCount += len(static.GetListenerConfigs())
					clustersCount += len(static.GetClusterConfigs())
					routesCount += len(static.GetRouteConfigs())
				}
				if dynamic != nil {
					listenersCount += len(dynamic.GetListenerConfigs())
					clustersCount += len(dynamic.GetClusterConfigs())
					routesCount += len(dynamic.GetRouteConfigs())
				}
			}
		} else {
			if respKN != nil {
				respKN.Body.Close()
			}
			// Try dual-engine
			respDE, err := http.Get(fmt.Sprintf("http://%s/debug/config_dump/dual-engine", fw.Address()))
			if err == nil && respDE.StatusCode == http.StatusOK {
				mode = "dual-engine"
				bodyDE, _ := io.ReadAll(respDE.Body)
				respDE.Body.Close()
				var deDump workloadDump
				if json.Unmarshal(bodyDE, &deDump) == nil {
					listenersCount = len(deDump.Workloads)
					clustersCount = len(deDump.Services)
					routesCount = len(deDump.Policies)
				}
			} else if respDE != nil {
				respDE.Body.Close()
			}
		}

		fw.Close()

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
			nodeName, podName, mode, vStr, listenersCount, clustersCount, routesCount)
	}

	_ = w.Flush()
	fmt.Println()
	return nil
}
