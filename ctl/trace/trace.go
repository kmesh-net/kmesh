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

package trace

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	cluster "kmesh.net/kmesh/api/v2/cluster"
	listener "kmesh.net/kmesh/api/v2/listener"
	route "kmesh.net/kmesh/api/v2/route"
	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("kmeshctl/trace")

func NewCmd() *cobra.Command {
	var srcIP string
	var dstIP string
	var port int

	cmd := &cobra.Command{
		Use:   "trace <kmesh-daemon-pod> --dst <dest-ip> --port <port>",
		Short: "Simulate a traffic request path lookup in the Kmesh engine config",
		Example: `  # Trace request to httpbin ClusterIP:
  kmeshctl trace kmesh-tclf6 --dst 10.96.46.87 --port 80`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if dstIP == "" || port == 0 {
				log.Errorf("Error: --dst and --port flags are required")
				os.Exit(1)
			}
			if err := RunTrace(cmd, args[0], srcIP, dstIP, port); err != nil {
				log.Errorf("Error: %v", err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVar(&srcIP, "src", "", "Source IP (optional)")
	cmd.Flags().StringVar(&dstIP, "dst", "", "Destination IP")
	cmd.Flags().IntVar(&port, "port", 0, "Destination Port")
	return cmd
}

func RunTrace(cmd *cobra.Command, podName, srcIP, dstIP string, port int) error {
	cli, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create cli client: %v", err)
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		return fmt.Errorf("failed to create port forwarder: %v", err)
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
		return fmt.Errorf("failed to read HTTP response: %v", err)
	}

	configDump := &adminv2.ConfigDump{}
	if err := protojson.Unmarshal(body, configDump); err != nil {
		return fmt.Errorf("failed to parse config dump: %v", err)
	}

	dstUint := ipStrToUint32(dstIP)

	fmt.Printf("\nSIMULATING TRAFFIC PATH: %s → %s:%d\n", getSrcString(srcIP), dstIP, port)
	fmt.Println(strings.Repeat("═", 65))

	static, dynamic := configDump.GetStaticResources(), configDump.GetDynamicResources()

	// Step 1: Find Matching Listener
	var matchedListener *listener.Listener
	findListener := func(res *adminv2.ConfigResources) {
		if res == nil || matchedListener != nil {
			return
		}
		for _, l := range res.GetListenerConfigs() {
			if sa := l.GetAddress(); sa != nil {
				lIpv4 := sa.GetIpv4()
				lPort := parsePort(sa.GetPort())
				// Match exact IP and Port, or Wildcard IP (0.0.0.0 / 0) and exact Port
				if (lIpv4 == dstUint || lIpv4 == 0) && int(lPort) == port {
					matchedListener = l
					return
				}
			}
		}
	}
	findListener(static)
	findListener(dynamic)

	if matchedListener == nil {
		fmt.Printf("STEP 1: [✗] NO LISTENER MATCHED for target %s:%d\n", dstIP, port)
		fmt.Println("Result: Traffic will bypass Kmesh and use default OS routing.")
		return nil
	}

	fmt.Printf("STEP 1: [✓] LISTENER MATCHED\n")
	fmt.Printf("  Name:    %s\n", matchedListener.GetName())
	if sa := matchedListener.GetAddress(); sa != nil {
		fmt.Printf("  Address: %s:%d\n", uint32ToIPStr(sa.GetIpv4()), parsePort(sa.GetPort()))
	}

	// Step 2: Parse Filters & Route Configuration
	var routeConfigName string
	var directCluster string
	isHTTP := false

	for _, fc := range matchedListener.GetFilterChains() {
		for _, f := range fc.GetFilters() {
			if f.GetName() == "envoy.filters.network.http_connection_manager" {
				isHTTP = true
				if hcm := f.GetHttpConnectionManager(); hcm != nil {
					routeConfigName = hcm.GetRouteConfigName()
					if routeConfigName == "" && hcm.GetRouteConfig() != nil {
						routeConfigName = hcm.GetRouteConfig().GetName()
					}
				}
			} else if f.GetName() == "envoy.filters.network.tcp_proxy" {
				if tp := f.GetTcpProxy(); tp != nil {
					directCluster = tp.GetCluster()
				}
			}
		}
	}

	var targetCluster string

	if isHTTP && routeConfigName != "" {
		fmt.Printf("STEP 2: [✓] HTTP FILTER CHAIN FOUND\n")
		fmt.Printf("  Route Configuration Name: %s\n", routeConfigName)

		// Find Route config
		var matchedRoute *route.RouteConfiguration
		findRoute := func(res *adminv2.ConfigResources) {
			if res == nil || matchedRoute != nil {
				return
			}
			for _, r := range res.GetRouteConfigs() {
				if r.GetName() == routeConfigName {
					matchedRoute = r
					return
				}
			}
		}
		findRoute(static)
		findRoute(dynamic)

		if matchedRoute == nil {
			fmt.Printf("  [✗] ROUTE CONFIGURATION NOT FOUND in Kmesh dump\n")
			return nil
		}

		// Find matching virtual host (we default to the first one or match host domain if available)
		var matchedVirtualHost *route.VirtualHost
		if len(matchedRoute.GetVirtualHosts()) > 0 {
			matchedVirtualHost = matchedRoute.GetVirtualHosts()[0] // default fallback
			// Try to match domain
			for _, vh := range matchedRoute.GetVirtualHosts() {
				for _, dom := range vh.GetDomains() {
					if dom == "*" || dom == dstIP {
						matchedVirtualHost = vh
						break
					}
				}
			}
		}

		if matchedVirtualHost == nil {
			fmt.Printf("  [✗] NO VIRTUAL HOST MATCHED in route configuration\n")
			return nil
		}

		fmt.Printf("  Virtual Host Matched: %s (Domains: %s)\n",
			matchedVirtualHost.GetName(), strings.Join(matchedVirtualHost.GetDomains(), ", "))

		// Match the route destination cluster
		if len(matchedVirtualHost.GetRoutes()) > 0 {
			r := matchedVirtualHost.GetRoutes()[0]
			if routeAction := r.GetRoute(); routeAction != nil {
				targetCluster = routeAction.GetCluster()
			}
		}
	} else if directCluster != "" {
		fmt.Printf("STEP 2: [✓] TCP PROXY FILTER CHAIN FOUND\n")
		targetCluster = directCluster
	}

	if targetCluster == "" {
		fmt.Printf("STEP 2: [✗] NO TARGET CLUSTER RESOLVED\n")
		return nil
	}

	fmt.Printf("STEP 3: [✓] TARGET CLUSTER RESOLVED\n")
	fmt.Printf("  Cluster Name: %s\n", targetCluster)

	// Step 4: Find Cluster and Backend Endpoints
	var matchedCluster *cluster.Cluster
	findCluster := func(res *adminv2.ConfigResources) {
		if res == nil || matchedCluster != nil {
			return
		}
		for _, c := range res.GetClusterConfigs() {
			if c.GetName() == targetCluster {
				matchedCluster = c
				return
			}
		}
	}
	findCluster(static)
	findCluster(dynamic)

	if matchedCluster == nil {
		fmt.Printf("STEP 4: [✗] CLUSTER NOT FOUND in Kmesh active config list\n")
		return nil
	}

	fmt.Printf("STEP 4: [✓] CLUSTER BACKEND ENDPOINTS FOUND\n")
	fmt.Printf("  Load Balancing Policy: %s\n", matchedCluster.GetLbPolicy().String())

	endpoints := matchedCluster.GetLoadAssignment().GetEndpoints()
	if len(endpoints) == 0 {
		fmt.Println("  [✗] NO ACTIVE POD ENDPOINTS REGISTERED (All backends are down/empty)")
		return nil
	}

	count := 0
	for _, ep := range endpoints {
		weight := ep.GetLoadBalancingWeight()
		for _, lbEp := range ep.GetLbEndpoints() {
			epAddr := lbEp.GetAddress()
			epIP := uint32ToIPStr(epAddr.GetIpv4())
			epPort := parsePort(epAddr.GetPort())
			fmt.Printf("  → Endpoint %d: %s:%d (Weight: %d)\n", count+1, epIP, epPort, weight)
			count++
		}
	}

	fmt.Println(strings.Repeat("═", 65))
	fmt.Printf("RESULT: Kmesh will successfully intercept and redirect this connection.\n")

	return nil
}

func getSrcString(src string) string {
	if src == "" {
		return "Any Client Pod"
	}
	return src
}

func ipStrToUint32(ipStr string) uint32 {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		// Try parsing as int directly
		val, err := strconv.Atoi(ipStr)
		if err == nil {
			return uint32(val)
		}
		return 0
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(ip4)
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
