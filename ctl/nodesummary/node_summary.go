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
	"sort"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var log = logger.NewLoggerScope("kmeshctl/node-summary")

var httpClient = &http.Client{Timeout: 10 * time.Second}

type workloadDump struct {
	Workloads []interface{} `json:"workloads"`
	Services  []interface{} `json:"services"`
	Policies  []interface{} `json:"policies"`
}

type summaryRow struct {
	nodeName       string
	podName        string
	mode           string
	vStr           string
	listenersCount int
	clustersCount  int
	routesCount    int
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

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		rows = make([]summaryRow, 0, len(podList.Items))
	)

	for _, pod := range podList.Items {
		wg.Add(1)
		go func(cli kube.CLIClient, podName, nodeName string) {
			defer wg.Done()
			row := fetchRow(cli, podName, nodeName)
			mu.Lock()
			rows = append(rows, row)
			mu.Unlock()
		}(cli, pod.GetName(), pod.Spec.NodeName)
	}
	wg.Wait()

	sort.Slice(rows, func(i, j int) bool {
		if rows[i].nodeName != rows[j].nodeName {
			return rows[i].nodeName < rows[j].nodeName
		}
		return rows[i].podName < rows[j].podName
	})

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "\nNODE_NAME\tKMESH_POD\tMODE\tVERSION\tLISTENERS/WORKLOADS\tCLUSTERS/SERVICES\tROUTES/POLICIES")
	for _, r := range rows {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
			r.nodeName, r.podName, r.mode, r.vStr, r.listenersCount, r.clustersCount, r.routesCount)
	}
	_ = w.Flush()
	fmt.Println()
	return nil
}

func fetchRow(cli kube.CLIClient, podName, nodeName string) summaryRow {
	if nodeName == "" {
		nodeName = "-"
	}
	row := summaryRow{nodeName: nodeName, podName: podName, mode: "unknown", vStr: "-"}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return row
	}
	if err := fw.Start(); err != nil {
		fw.Close()
		row.mode = "Offline"
		return row
	}
	defer fw.Close()

	respV, err := httpClient.Get(fmt.Sprintf("http://%s/version", fw.Address()))
	if err == nil && respV.StatusCode == http.StatusOK {
		bodyV, readErr := io.ReadAll(respV.Body)
		respV.Body.Close()
		if readErr == nil {
			var v version.Info
			if json.Unmarshal(bodyV, &v) == nil && v.GitVersion != "" {
				row.vStr = v.GitVersion
			}
		}
	} else if respV != nil {
		respV.Body.Close()
	}

	respKN, err := httpClient.Get(fmt.Sprintf("http://%s/debug/config_dump/kernel-native", fw.Address()))
	if err == nil && respKN.StatusCode == http.StatusOK {
		row.mode = "kernel-native"
		bodyKN, readErr := io.ReadAll(respKN.Body)
		respKN.Body.Close()
		if readErr != nil {
			row.mode = "Error"
			return row
		}
		configDump := &adminv2.ConfigDump{}
		if protojson.Unmarshal(bodyKN, configDump) == nil {
			static, dynamic := configDump.GetStaticResources(), configDump.GetDynamicResources()
			if static != nil {
				row.listenersCount += len(static.GetListenerConfigs())
				row.clustersCount += len(static.GetClusterConfigs())
				row.routesCount += len(static.GetRouteConfigs())
			}
			if dynamic != nil {
				row.listenersCount += len(dynamic.GetListenerConfigs())
				row.clustersCount += len(dynamic.GetClusterConfigs())
				row.routesCount += len(dynamic.GetRouteConfigs())
			}
		}
		return row
	} else if respKN != nil {
		respKN.Body.Close()
	}

	respDE, err := httpClient.Get(fmt.Sprintf("http://%s/debug/config_dump/dual-engine", fw.Address()))
	if err == nil && respDE.StatusCode == http.StatusOK {
		row.mode = "dual-engine"
		bodyDE, readErr := io.ReadAll(respDE.Body)
		respDE.Body.Close()
		if readErr != nil {
			row.mode = "Error"
			return row
		}
		var deDump workloadDump
		if json.Unmarshal(bodyDE, &deDump) == nil {
			row.listenersCount = len(deDump.Workloads)
			row.clustersCount = len(deDump.Services)
			row.routesCount = len(deDump.Policies)
		}
	} else if respDE != nil {
		respDE.Body.Close()
	}

	return row
}
