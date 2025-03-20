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

package status

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils"
)

type Workload struct {
	Uid                   string            `json:"uid,omitempty"`
	Addresses             []string          `json:"addresses"`
	Waypoint              string            `json:"waypoint,omitempty"`
	Protocol              string            `json:"protocol"`
	Name                  string            `json:"name"`
	Namespace             string            `json:"namespace"`
	ServiceAccount        string            `json:"serviceAccount"`
	WorkloadName          string            `json:"workloadName"`
	WorkloadType          string            `json:"workloadType"`
	CanonicalName         string            `json:"canonicalName"`
	CanonicalRevision     string            `json:"canonicalRevision"`
	ClusterID             string            `json:"clusterId"`
	TrustDomain           string            `json:"trustDomain,omitempty"`
	Locality              Locality          `json:"locality,omitempty"`
	Node                  string            `json:"node"`
	Network               string            `json:"network,omitempty"`
	Status                string            `json:"status"`
	ApplicationTunnel     ApplicationTunnel `json:"applicationTunnel,omitempty"`
	Services              []string          `json:"services,omitempty"`
	AuthorizationPolicies []string          `json:"authorizationPolicies,omitempty"`
}

type Locality struct {
	Region  string `json:"region,omitempty"`
	Zone    string `json:"zone,omitempty"`
	Subzone string `json:"subzone,omitempty"`
}

type ApplicationTunnel struct {
	Protocol string `json:"protocol"`
	Port     uint32 `json:"port,omitempty"`
}

type Waypoint struct {
	Destination string `json:"destination"`
}

type LoadBalancer struct {
	Mode               string   `json:"mode"`
	RoutingPreferences []string `json:"routingPreferences"`
}

type Service struct {
	Name         string              `json:"name"`
	Namespace    string              `json:"namespace"`
	Hostname     string              `json:"hostname"`
	Addresses    []string            `json:"vips"`
	Ports        []*workloadapi.Port `json:"ports"`
	LoadBalancer *LoadBalancer       `json:"loadBalancer"`
	Waypoint     *Waypoint           `json:"waypoint"`
}

type AuthorizationPolicy struct {
	Name      string           `json:"name"`
	Namespace string           `json:"namespace"`
	Scope     string           `json:"scope"`
	Action    string           `json:"action"`
	Rules     []*security.Rule `json:"rules"`
}

type NetworkAddress struct {
	// Network represents the network this address is on.
	Network string
	// Address presents the IP (v4 or v6).
	Address net.IP
}

func ConvertWorkload(w *workloadapi.Workload) *Workload {
	ips := make([]string, 0, len(w.Addresses))
	for _, addr := range w.Addresses {
		ips = append(ips, net.IP(addr).String())
	}
	var waypoint string
	if waypointAddress := w.Waypoint.GetAddress(); waypointAddress != nil {
		waypoint = waypointAddress.Network + "/" + net.IP(waypointAddress.Address).String()
	} else if host := w.Waypoint.GetHostname(); host != nil {
		waypoint = host.Namespace + "/" + host.Hostname
	}

	out := &Workload{
		Uid:                   w.Uid,
		Addresses:             ips,
		Waypoint:              waypoint,
		Protocol:              w.TunnelProtocol.String(),
		Name:                  w.Name,
		Namespace:             w.Namespace,
		ServiceAccount:        w.ServiceAccount,
		WorkloadName:          w.WorkloadName,
		WorkloadType:          w.WorkloadType.String(),
		CanonicalName:         w.CanonicalName,
		CanonicalRevision:     w.CanonicalRevision,
		ClusterID:             w.ClusterId,
		TrustDomain:           w.TrustDomain,
		Node:                  w.Node,
		Network:               w.Network,
		Status:                w.Status.String(),
		AuthorizationPolicies: w.AuthorizationPolicies,
	}
	if w.Locality != nil {
		out.Locality = Locality{Region: w.Locality.Region, Zone: w.Locality.Zone, Subzone: w.Locality.Subzone}
	}
	if w.ApplicationTunnel != nil {
		out.ApplicationTunnel = ApplicationTunnel{Protocol: w.ApplicationTunnel.Protocol.String(), Port: w.ApplicationTunnel.Port}
	}

	if len(w.Services) > 0 {
		services := make([]string, 0, len(w.Services))
		for svc := range w.Services {
			services = append(services, svc)
		}
		out.Services = services
	}

	return out
}

func ConvertService(s *workloadapi.Service) *Service {
	vips := make([]string, 0, len(s.Addresses))
	for _, addr := range s.Addresses {
		vips = append(vips, addr.Network+"/"+net.IP(addr.Address).String())
	}
	var waypoint string
	if waypointAddress := s.Waypoint.GetAddress(); waypointAddress != nil {
		waypoint = waypointAddress.Network + "/" + net.IP(waypointAddress.Address).String()
	} else if host := s.Waypoint.GetHostname(); host != nil {
		waypoint = host.Namespace + "/" + host.Hostname
	}

	out := &Service{
		Name:      s.Name,
		Namespace: s.Namespace,
		Hostname:  s.Hostname,
		Addresses: vips,
		Ports:     s.Ports,
		Waypoint:  &Waypoint{Destination: waypoint},
	}

	if s.LoadBalancing != nil {
		routingPreferences := make([]string, 0, len(s.LoadBalancing.RoutingPreference))
		for _, p := range s.LoadBalancing.RoutingPreference {
			routingPreferences = append(routingPreferences, p.String())
		}
		out.LoadBalancer = &LoadBalancer{Mode: s.LoadBalancing.Mode.String(), RoutingPreferences: routingPreferences}
	}

	return out
}

func ConvertAuthorizationPolicy(p *security.Authorization) *AuthorizationPolicy {
	out := &AuthorizationPolicy{
		Name:      p.GetName(),
		Namespace: p.GetNamespace(),
		Scope:     p.GetScope().String(),
		Action:    p.GetAction().String(),
		Rules:     p.Rules,
	}

	return out
}

type prettyArray[T any] []T

func (a prettyArray[T]) MarshalJSON() ([]byte, error) {
	prettified := make([]string, len(a))
	for i, elem := range a {
		prettified[i] = fmt.Sprintf("%v", elem)
	}

	return json.Marshal(strings.Join(prettified, ", "))
}

type BpfServiceValue struct {
	// EndpointCount is the number of endpoints for each priority.
	EndpointCount prettyArray[uint32] `json:"endpointCount"`
	LbPolicy      string              `json:"lbPolicy"`
	ServicePort   prettyArray[uint32] `json:"servicePort,omitempty"`
	TargetPort    prettyArray[uint32] `json:"targetPort,omitempty"`
	WaypointAddr  string              `json:"waypointAddr,omitempty"`
	WaypointPort  uint32              `json:"waypointPort,omitempty"`
}

type BpfBackendValue struct {
	Ip           string   `json:"ip"`
	ServiceCount uint32   `json:"serviceCount"`
	Services     []string `json:"services"`
	WaypointAddr string   `json:"waypointAddr,omitempty"`
	WaypointPort uint32   `json:"waypointPort,omitempty"`
}

type BpfFrontendValue struct {
	UpstreamId string `json:"upstreamId,omitempty"`
}

type BpfWorkloadPolicyValue struct {
	PolicyIds []string `json:"policyIds,omitempty"`
}

type BpfEndpointValue struct {
	BackendUid string `json:"backendUid,omitempty"`
}

type WorkloadBpfDump struct {
	hashName *utils.HashName

	WorkloadPolicies []BpfWorkloadPolicyValue `json:"workloadPolicies"`
	Backends         []BpfBackendValue        `json:"backends"`
	Endpoints        []BpfEndpointValue       `json:"endpoints"`
	Frontends        []BpfFrontendValue       `json:"frontends"`
	Services         []BpfServiceValue        `json:"services"`
}

func NewWorkloadBpfDump(hashName *utils.HashName) WorkloadBpfDump {
	return WorkloadBpfDump{hashName: hashName}
}

func (wd WorkloadBpfDump) WithWorkloadPolicies(workloadPolicies []bpfcache.WorkloadPolicyValue) WorkloadBpfDump {
	converted := make([]BpfWorkloadPolicyValue, 0, len(workloadPolicies))
	for _, policy := range workloadPolicies {
		policyIds := []string{}
		for _, id := range policy.PolicyIds {
			policyIds = append(policyIds, wd.hashName.NumToStr(id))
		}
		converted = append(converted, BpfWorkloadPolicyValue{
			PolicyIds: policyIds,
		})
	}
	wd.WorkloadPolicies = converted
	return wd
}

func (wd WorkloadBpfDump) WithBackends(backends []bpfcache.BackendValue) WorkloadBpfDump {
	converted := make([]BpfBackendValue, 0, len(backends))
	for _, backend := range backends {
		waypointAddr := ""
		if backend.WaypointAddr != [16]byte{} {
			waypointAddr = nets.IpString(backend.WaypointAddr)
		}
		bac := BpfBackendValue{
			Ip:           nets.IpString(backend.Ip),
			ServiceCount: backend.ServiceCount,
			WaypointAddr: waypointAddr,
			WaypointPort: nets.ConvertPortToLittleEndian(backend.WaypointPort),
		}
		services := make([]string, 0, len(backend.Services))
		for _, s := range backend.Services {
			svc := wd.hashName.NumToStr(s)
			if svc == "" {
				continue
			}
			services = append(services, svc)
		}
		bac.Services = services
		converted = append(converted, bac)
	}
	wd.Backends = converted
	return wd
}

func (wd WorkloadBpfDump) WithEndpoints(endpoints []bpfcache.EndpointValue) WorkloadBpfDump {
	converted := make([]BpfEndpointValue, 0, len(endpoints))
	for _, endpoint := range endpoints {
		converted = append(converted, BpfEndpointValue{
			BackendUid: wd.hashName.NumToStr(endpoint.BackendUid),
		})
	}
	wd.Endpoints = converted
	return wd
}

func (wd WorkloadBpfDump) WithFrontends(frontends []bpfcache.FrontendValue) WorkloadBpfDump {
	converted := make([]BpfFrontendValue, 0, len(frontends))
	for _, frontend := range frontends {
		converted = append(converted, BpfFrontendValue{
			UpstreamId: wd.hashName.NumToStr(frontend.UpstreamId),
		})
	}
	wd.Frontends = converted
	return wd
}

func (wd WorkloadBpfDump) WithServices(services []bpfcache.ServiceValue) WorkloadBpfDump {
	converted := make([]BpfServiceValue, 0, len(services))
	for _, s := range services {
		waypointAddr := ""
		if s.WaypointAddr != [16]byte{} {
			waypointAddr = nets.IpString(s.WaypointAddr)
		}
		svc := BpfServiceValue{
			EndpointCount: []uint32{},
			LbPolicy:      workloadapi.LoadBalancing_Mode_name[int32(s.LbPolicy)],
			WaypointAddr:  waypointAddr,
			WaypointPort:  nets.ConvertPortToLittleEndian(s.WaypointPort),
		}

		for _, c := range s.EndpointCount {
			svc.EndpointCount = append(svc.EndpointCount, c)
		}

		for _, p := range s.ServicePort {
			if p == 0 {
				continue
			}
			svc.ServicePort = append(svc.ServicePort, nets.ConvertPortToLittleEndian(p))
		}

		for _, p := range s.TargetPort {
			if p == 0 {
				continue
			}
			svc.TargetPort = append(svc.TargetPort, nets.ConvertPortToLittleEndian(p))
		}

		converted = append(converted, svc)
	}
	wd.Services = converted
	return wd
}
