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
package dns

import (
	"fmt"
	"net"

	"istio.io/istio/pilot/pkg/serviceregistry/provider"
	dnsProto "istio.io/istio/pkg/dns/proto"
	"istio.io/istio/pkg/env"
	"istio.io/istio/pkg/slices"
	netutil "istio.io/istio/pkg/util/net"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

var (
	clusterDomain = env.Register("CLUSTER_DOMAIN", "cluster.local", "Cluster domain name.").Get()
)

type NameTableBuilder interface {
	BuildNameTable() *dnsProto.NameTable
}

type nameTableBuilder struct {
	serviceCache  cache.ServiceCache
	workloadCache cache.WorkloadCache
}

func NewNameTableBuilder(serviceCache cache.ServiceCache, workloadCache cache.WorkloadCache) NameTableBuilder {
	return &nameTableBuilder{
		serviceCache:  serviceCache,
		workloadCache: workloadCache,
	}
}

// THIS FUNC IS MODIFIED BASED ON istio.io/istio/pkg/dns/server/name_table.go
//
// BuildNameTable produces a table of hostnames and their associated IPs that can then
// be used by the agent to resolve DNS. This logic is always active. However, local DNS resolution
// will only be effective if DNS capture is enabled in the proxy
func (b *nameTableBuilder) BuildNameTable() *dnsProto.NameTable {
	out := &dnsProto.NameTable{
		Table: make(map[string]*dnsProto.NameTable_NameInfo),
	}

	workloads := b.workloadCache.List()
	for _, svc := range b.serviceCache.List() {
		addressList := []string{}

		headless := len(svc.Addresses) == 0
		for _, svcAddress := range svc.Addresses {
			ip := net.IP(svcAddress.Address)

			if ip.IsUnspecified() {
				headless = true
				break
			}

			// Filter out things we cannot parse as IP. Generally this means CIDRs, as anything else
			// should be caught in validation.
			if !netutil.IsValidIPAddress(ip.String()) {
				continue
			}

			addressList = append(addressList, ip.String())
		}

		// headless
		if headless {
			endpoints := lookupHeadlessEndpoints(svc, workloads)
			for _, endpoint := range endpoints {
				for _, address := range endpoint.Addresses {
					ip := net.IP(address)
					addressList = append(addressList, ip.String())
				}
			}
		}

		hostName := svc.Hostname
		registry := guessServiceRegistry(svc)
		if ni, f := out.Table[hostName]; !f {
			nameInfo := &dnsProto.NameTable_NameInfo{
				Ips:      addressList,
				Registry: registry.String(),
			}
			if registry == provider.Kubernetes {
				// The agent will take care of resolving a, a.ns, a.ns.svc, etc.
				// No need to provide a DNS entry for each variant.
				//
				// NOTE: This is not done for Kubernetes Multi-Cluster Services (MCS) hosts, in order
				// to avoid conflicting with the entries for the regular (cluster.local) service.
				nameInfo.Namespace = svc.Namespace
				nameInfo.Shortname = svc.Name
			}
			out.Table[hostName] = nameInfo
		} else if provider.ID(ni.Registry) != provider.Kubernetes {
			// 2 possible cases:
			// 1. If the SE has multiple addresses(vips) specified, merge the ips
			// 2. If the previous SE is a decorator of the k8s service, give precedence to the k8s service
			if registry == provider.Kubernetes {
				ni.Ips = addressList
				ni.Registry = string(provider.Kubernetes)
				ni.Namespace = svc.Namespace
				ni.Shortname = svc.Name
			} else {
				ni.Ips = append(ni.Ips, addressList...)
			}
		}
	}

	return out
}

func lookupHeadlessEndpoints(svc *workloadapi.Service, workloads []*workloadapi.Workload) []*workloadapi.Workload {
	key := fmt.Sprintf("%s/%s", svc.Namespace, svc.Hostname)
	return slices.Filter(workloads, func(w *workloadapi.Workload) bool {
		if len(w.Addresses) == 0 {
			return false
		}

		for _, address := range w.Addresses {
			ip := net.IP(address)
			if !netutil.IsValidIPAddress(ip.String()) {
				return false
			}
		}

		for service := range w.Services {
			if service == key {
				return true
			}
		}
		return false
	})
}

// guessServiceRegistry try to guess whether the service is a kubernetes or an external service
// by checking if the host name of the service in format <service-name>.<namespace>.svc.<cluster-domain>
func guessServiceRegistry(svc *workloadapi.Service) provider.ID {
	kubernetesSvcHostName := fmt.Sprintf("%s.%s.svc.%s", svc.Name, svc.Namespace, clusterDomain)
	if svc.Hostname == kubernetesSvcHostName {
		return provider.Kubernetes
	}
	return provider.External
}
