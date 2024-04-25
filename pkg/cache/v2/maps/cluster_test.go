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

package maps

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/rand"

	cluster_v2 "kmesh.net/kmesh/api/v2/cluster"
	core_v2 "kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/endpoint"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/utils/test"
)

func BenchmarkClusterMapFlush(b *testing.B) {
	t := &testing.T{}
	test.InitBpfMap(t)
	t.Cleanup(test.CleanupBpfMap)

	cluster := cluster_v2.Cluster{
		ApiStatus:      core_v2.ApiStatus_UPDATE,
		ConnectTimeout: uint32(1),
		CircuitBreakers: &cluster_v2.CircuitBreakers{
			MaxConnections:     uint32(4294967295),
			MaxPendingRequests: uint32(4294967295),
			MaxRequests:        uint32(4294967295),
			MaxRetries:         uint32(4294967295),
		},
		LoadAssignment: &endpoint.ClusterLoadAssignment{
			ClusterName: "inbound|9080|http|reviews.default.svc.cluster.local",
			Endpoints: []*endpoint.LocalityLbEndpoints{
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9090),
								Ipv4: nets.ConvertIpToUint32("192.168.127.240"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9091),
								Ipv4: nets.ConvertIpToUint32("192.168.127.241"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9092),
								Ipv4: nets.ConvertIpToUint32("192.168.127.242"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9293),
								Ipv4: nets.ConvertIpToUint32("192.168.127.243"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9294),
								Ipv4: nets.ConvertIpToUint32("192.168.127.244"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9095),
								Ipv4: nets.ConvertIpToUint32("192.168.127.245"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9096),
								Ipv4: nets.ConvertIpToUint32("192.168.127.246"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9097),
								Ipv4: nets.ConvertIpToUint32("192.168.127.247"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9098),
								Ipv4: nets.ConvertIpToUint32("192.168.127.248"),
							},
						},
					},
				},
				{
					LbEndpoints: []*endpoint.Endpoint{
						{
							Address: &core_v2.SocketAddress{
								Port: uint32(9099),
								Ipv4: nets.ConvertIpToUint32("192.168.127.249"),
							},
						},
					},
				},
			},
		},
		LbPolicy: cluster_v2.Cluster_ROUND_ROBIN,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cluster.Name = rand.String(6)
		_ = ClusterUpdate(cluster.Name, &cluster)
	}
}
