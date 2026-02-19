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

package dump

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	configDumpPrefix = "/debug/config_dump"
)

var log = logger.NewLoggerScope("kmeshctl/dump")

func NewCmd() *cobra.Command {
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump config of kernel-native or dual-engine mode",
		Example: `# Kernel Native mode (table output):
kmeshctl dump <kmesh-daemon-pod> kernel-native

# Dual Engine mode (table output):
kmeshctl dump <kmesh-daemon-pod> dual-engine

# Output as raw JSON:
kmeshctl dump <kmesh-daemon-pod> kernel-native -o json`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			_ = RunDump(cmd, args, outputFormat)
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table or json")
	return cmd
}

func RunDump(cmd *cobra.Command, args []string, outputFormat string) error {
	podName := args[0]
	mode := args[1]
	if mode != constants.KernelNativeMode && mode != constants.DualEngineMode {
		log.Errorf("Error: Argument must be 'kernel-native' or 'dual-engine'")
		os.Exit(1)
	}

	cli, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		log.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	if err := fw.Start(); err != nil {
		log.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}

	url := fmt.Sprintf("http://%s%s/%s", fw.Address(), configDumpPrefix, mode)
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("failed to make HTTP request: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("failed to read HTTP response body: %v", err)
		os.Exit(1)
	}

	if outputFormat == "json" {
		fmt.Println(string(body))
		return nil
	}

	switch mode {
	case constants.KernelNativeMode:
		printKernelNativeTable(body)
	case constants.DualEngineMode:
		printDualEngineTable(body)
	}

	return nil
}

// printKernelNativeTable parses and displays kernel-native config dump as tables.
// Static and dynamic resources of the same type are consolidated under a single header.
func printKernelNativeTable(body []byte) {
	configDump := &adminv2.ConfigDump{}
	if err := protojson.Unmarshal(body, configDump); err != nil {
		log.Errorf("failed to parse config dump: %v, falling back to raw output", err)
		fmt.Println(string(body))
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	static, dynamic := configDump.GetStaticResources(), configDump.GetDynamicResources()

	// Clusters
	if (static != nil && len(static.GetClusterConfigs()) > 0) || (dynamic != nil && len(dynamic.GetClusterConfigs()) > 0) {
		fmt.Fprintln(w, "NAME\tLB_POLICY\tCONNECT_TIMEOUT")
		if static != nil {
			for _, c := range static.GetClusterConfigs() {
				fmt.Fprintf(w, "%s\t%s\t%d\n", c.GetName(), c.GetLbPolicy().String(), c.GetConnectTimeout())
			}
		}
		if dynamic != nil {
			for _, c := range dynamic.GetClusterConfigs() {
				fmt.Fprintf(w, "%s\t%s\t%d\n", c.GetName(), c.GetLbPolicy().String(), c.GetConnectTimeout())
			}
		}
		_ = w.Flush()
		fmt.Println()
	}

	// Listeners
	if (static != nil && len(static.GetListenerConfigs()) > 0) || (dynamic != nil && len(dynamic.GetListenerConfigs()) > 0) {
		fmt.Fprintln(w, "NAME\tADDRESS\tPORT\tFILTER_CHAINS")
		printListeners := func(resources *adminv2.ConfigResources) {
			for _, l := range resources.GetListenerConfigs() {
				addr, port := "-", "-"
				if sa := l.GetAddress(); sa != nil {
					addr = uint32ToIPStr(sa.GetIpv4())
					port = fmt.Sprintf("%d", sa.GetPort())
				}
				var fcNames []string
				for _, fc := range l.GetFilterChains() {
					fcNames = append(fcNames, fc.GetName())
				}
				chains := strings.Join(fcNames, ",")
				if chains == "" {
					chains = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", l.GetName(), addr, port, chains)
			}
		}
		if static != nil {
			printListeners(static)
		}
		if dynamic != nil {
			printListeners(dynamic)
		}
		_ = w.Flush()
		fmt.Println()
	}

	// Routes
	if (static != nil && len(static.GetRouteConfigs()) > 0) || (dynamic != nil && len(dynamic.GetRouteConfigs()) > 0) {
		fmt.Fprintln(w, "ROUTE\tVIRTUAL_HOST\tDOMAINS")
		printRoutes := func(resources *adminv2.ConfigResources) {
			for _, r := range resources.GetRouteConfigs() {
				for _, vh := range r.GetVirtualHosts() {
					fmt.Fprintf(w, "%s\t%s\t%s\n", r.GetName(), vh.GetName(), strings.Join(vh.GetDomains(), ","))
				}
			}
		}
		if static != nil {
			printRoutes(static)
		}
		if dynamic != nil {
			printRoutes(dynamic)
		}
		_ = w.Flush()
		fmt.Println()
	}
}

// workloadDump mirrors the JSON structure returned by the dual-engine config dump endpoint.
type workloadDump struct {
	Workloads []workloadEntry `json:"workloads"`
	Services  []serviceEntry  `json:"services"`
	Policies  []policyEntry   `json:"policies"`
}

type workloadEntry struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Addresses []string `json:"addresses"`
	Protocol  string   `json:"protocol"`
	Status    string   `json:"status"`
}

type serviceEntry struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Hostname  string   `json:"hostname"`
	Addresses []string `json:"vips"`
}

type policyEntry struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Scope     string `json:"scope"`
	Action    string `json:"action"`
}

// printDualEngineTable parses and displays dual-engine config dump as tables.
func printDualEngineTable(body []byte) {
	var dump workloadDump
	if err := json.Unmarshal(body, &dump); err != nil {
		log.Errorf("failed to parse workload dump: %v, falling back to raw output", err)
		fmt.Println(string(body))
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	if len(dump.Workloads) > 0 {
		fmt.Fprintln(w, "NAME\tNAMESPACE\tADDRESSES\tPROTOCOL\tSTATUS")
		for _, wl := range dump.Workloads {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
				wl.Name,
				wl.Namespace,
				strings.Join(wl.Addresses, ","),
				wl.Protocol,
				wl.Status,
			)
		}
		_ = w.Flush()
		fmt.Println()
	}

	if len(dump.Services) > 0 {
		fmt.Fprintln(w, "NAME\tNAMESPACE\tHOSTNAME\tVIPS")
		for _, svc := range dump.Services {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				svc.Name,
				svc.Namespace,
				svc.Hostname,
				strings.Join(svc.Addresses, ","),
			)
		}
		_ = w.Flush()
		fmt.Println()
	}

	if len(dump.Policies) > 0 {
		fmt.Fprintln(w, "NAME\tNAMESPACE\tSCOPE\tACTION")
		for _, p := range dump.Policies {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				p.Name,
				p.Namespace,
				p.Scope,
				p.Action,
			)
		}
		_ = w.Flush()
		fmt.Println()
	}
}

// uint32ToIPStr converts a little-endian uint32 to a dotted IPv4 string.
func uint32ToIPStr(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b).String()
}
