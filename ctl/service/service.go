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

package service

import (
	"encoding/binary"
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
	cluster "kmesh.net/kmesh/api/v2/cluster"
	listener "kmesh.net/kmesh/api/v2/listener"
	route "kmesh.net/kmesh/api/v2/route"
	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("kmeshctl/service")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service <kmesh-daemon-pod> <service-name>",
		Short: "Show all listener, route, and cluster configs for a specific service",
		Example: `  # Show details for httpbin service:
  kmeshctl service kmesh-tclf6 httpbin`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if err := RunService(cmd, args); err != nil {
				log.Errorf("Error: %v", err)
				os.Exit(1)
			}
		},
	}
	return cmd
}

func RunService(cmd *cobra.Command, args []string) error {
	podName := args[0]
	serviceName := strings.ToLower(args[1])

	cli, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %v", err)
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	if err := fw.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s/debug/config_dump/kernel-native", fw.Address())
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("failed to make HTTP request to status server: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read HTTP response body: %v", err)
	}

	configDump := &adminv2.ConfigDump{}
	if err := protojson.Unmarshal(body, configDump); err != nil {
		return fmt.Errorf("failed to parse config dump: %v", err)
	}

	static, dynamic := configDump.GetStaticResources(), configDump.GetDynamicResources()

	// --- Step 1: Collect matching routes and clusters ---
	matchingRouteNames := map[string]bool{}
	matchingClusterNames := map[string]bool{}

	var matchingRoutes []*route.RouteConfiguration
	var matchingClusters []*cluster.Cluster

	collectRoutes := func(res *adminv2.ConfigResources) {
		if res == nil {
			return
		}
		for _, r := range res.GetRouteConfigs() {
			matched := strings.Contains(strings.ToLower(r.GetName()), serviceName)
			if !matched {
				for _, vh := range r.GetVirtualHosts() {
					if strings.Contains(strings.ToLower(vh.GetName()), serviceName) {
						matched = true
						break
					}
				}
			}
			if matched {
				matchingRoutes = append(matchingRoutes, r)
				matchingRouteNames[r.GetName()] = true
			}
		}
	}
	collectClusters := func(res *adminv2.ConfigResources) {
		if res == nil {
			return
		}
		for _, c := range res.GetClusterConfigs() {
			if strings.Contains(strings.ToLower(c.GetName()), serviceName) {
				matchingClusters = append(matchingClusters, c)
				matchingClusterNames[c.GetName()] = true
			}
		}
	}

	collectRoutes(static)
	collectRoutes(dynamic)
	collectClusters(static)
	collectClusters(dynamic)

	// --- Step 2: Find listeners that reference matching routes or clusters ---
	// Listener names are IP_PORT format (e.g. 10.96.0.10_53), not service names.
	// We must correlate via filter chain content.
	var matchingListeners []*listener.Listener
	seenListeners := map[string]bool{}

	collectListeners := func(res *adminv2.ConfigResources) {
		if res == nil {
			return
		}
		for _, l := range res.GetListenerConfigs() {
			if seenListeners[l.GetName()] {
				continue
			}
			matched := false
			for _, fc := range l.GetFilterChains() {
				for _, f := range fc.GetFilters() {
					// HTTP filter: check route config name
					if hcm := f.GetHttpConnectionManager(); hcm != nil {
						rcName := hcm.GetRouteConfigName()
						if rcName == "" && hcm.GetRouteConfig() != nil {
							rcName = hcm.GetRouteConfig().GetName()
						}
						if matchingRouteNames[rcName] {
							matched = true
						}
					}
					// TCP filter: check cluster name
					if tp := f.GetTcpProxy(); tp != nil {
						if matchingClusterNames[tp.GetCluster()] {
							matched = true
						}
					}
				}
				if matched {
					break
				}
			}
			if matched {
				matchingListeners = append(matchingListeners, l)
				seenListeners[l.GetName()] = true
			}
		}
	}

	collectListeners(static)
	collectListeners(dynamic)

	// --- Print results ---
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)

	fmt.Printf("\nSERVICE FILTER: %s\n", serviceName)
	fmt.Println(strings.Repeat("═", 60))

	// Listeners table
	fmt.Fprintln(w, "\n[LISTENERS]")
	fmt.Fprintln(w, "NAME\tADDRESS\tPORT\tTYPE")
	if len(matchingListeners) == 0 {
		fmt.Fprintln(w, "<no matching listeners found>")
	}
	for _, l := range matchingListeners {
		addr, port := "-", "-"
		lType := "TCP"
		if sa := l.GetAddress(); sa != nil {
			addr = uint32ToIPStr(sa.GetIpv4())
			port = fmt.Sprintf("%d", parsePort(sa.GetPort()))
		}
		// Detect HTTP vs TCP from filter chains
		for _, fc := range l.GetFilterChains() {
			for _, f := range fc.GetFilters() {
				if f.GetHttpConnectionManager() != nil {
					lType = "HTTP"
				}
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", l.GetName(), addr, port, lType)
	}
	_ = w.Flush()

	// Routes table
	fmt.Fprintln(w, "\n[ROUTES]")
	fmt.Fprintln(w, "ROUTE_NAME\tVIRTUAL_HOST\tDOMAINS")
	if len(matchingRoutes) == 0 {
		fmt.Fprintln(w, "<no matching routes found>")
	}
	for _, r := range matchingRoutes {
		for _, vh := range r.GetVirtualHosts() {
			if strings.Contains(strings.ToLower(vh.GetName()), serviceName) ||
				strings.Contains(strings.ToLower(r.GetName()), serviceName) {
				fmt.Fprintf(w, "%s\t%s\t%s\n", r.GetName(), vh.GetName(), strings.Join(vh.GetDomains(), ","))
			}
		}
	}
	_ = w.Flush()

	// Clusters table
	fmt.Fprintln(w, "\n[CLUSTERS & ENDPOINTS]")
	fmt.Fprintln(w, "CLUSTER_NAME\tLB_POLICY\tENDPOINT_IP\tENDPOINT_PORT")
	if len(matchingClusters) == 0 {
		fmt.Fprintln(w, "<no matching clusters found>")
	}
	for _, c := range matchingClusters {
		lbPolicy := c.GetLbPolicy().String()
		endpoints := c.GetLoadAssignment().GetEndpoints()
		if len(endpoints) == 0 {
			fmt.Fprintf(w, "%s\t%s\t-\t-\n", c.GetName(), lbPolicy)
		} else {
			for _, ep := range endpoints {
				for _, lbEp := range ep.GetLbEndpoints() {
					epAddr := lbEp.GetAddress()
					epIP := uint32ToIPStr(epAddr.GetIpv4())
					epPort := fmt.Sprintf("%d", parsePort(epAddr.GetPort()))
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", c.GetName(), lbPolicy, epIP, epPort)
				}
			}
		}
	}
	_ = w.Flush()
	fmt.Println()

	return nil
}

func parsePort(p uint32) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(p))
	return binary.LittleEndian.Uint16(b)
}

func uint32ToIPStr(ip uint32) string {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, ip)
	return net.IP(b).String()
}
