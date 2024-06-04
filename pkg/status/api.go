/*
 * Copyright 2024 The Kmesh Authors.
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
	"net"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

type Workload struct {
	Uid               string            `json:"uid,omitempty"`
	Addresses         []string          `json:"addresses"`
	Waypoint          *Waypoint         `json:"waypoint,omitempty"`
	Protocol          string            `json:"protocol"`
	Name              string            `json:"name"`
	Namespace         string            `json:"namespace"`
	ServiceAccount    string            `json:"serviceAccount"`
	WorkloadName      string            `json:"workloadName"`
	WorkloadType      string            `json:"workloadType"`
	CanonicalName     string            `json:"canonicalName"`
	CanonicalRevision string            `json:"canonicalRevision"`
	ClusterID         string            `json:"clusterId"`
	TrustDomain       string            `json:"trustDomain,omitempty"`
	Locality          Locality          `json:"locality,omitempty"`
	Node              string            `json:"node"`
	Network           string            `json:"network,omitempty"`
	Status            string            `json:"status"`
	ApplicationTunnel ApplicationTunnel `json:"applicationTunnel,omitempty"`
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
		Uid:               w.Uid,
		Addresses:         ips,
		Waypoint:          &Waypoint{Destination: waypoint},
		Protocol:          w.TunnelProtocol.String(),
		Name:              w.Name,
		Namespace:         w.Namespace,
		ServiceAccount:    w.ServiceAccount,
		WorkloadName:      w.WorkloadName,
		WorkloadType:      w.WorkloadType.String(),
		CanonicalName:     w.CanonicalName,
		CanonicalRevision: w.CanonicalRevision,
		ClusterID:         w.ClusterId,
		TrustDomain:       w.TrustDomain,
		Node:              w.Node,
		Network:           w.Network,
		Status:            w.Status.String(),
	}
	if w.Locality != nil {
		out.Locality = Locality{Region: w.Locality.Region, Zone: w.Locality.Zone, Subzone: w.Locality.Subzone}
	}
	if w.ApplicationTunnel != nil {
		out.ApplicationTunnel = ApplicationTunnel{Protocol: w.ApplicationTunnel.Protocol.String(), Port: w.ApplicationTunnel.Port}
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
