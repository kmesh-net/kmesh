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
package bpfcache

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

func TestCalcLocalityLBPrio(t *testing.T) {
	// Create a sample LocalityCache instance
	localityCache := &LocalityCache{
		LocalityInfo: &localityInfo{
			region:    "region1",
			zone:      "zone1",
			subZone:   "subzone1",
			nodeName:  "node1",
			clusterId: "cluster1",
			network:   "network1",
		},
	}
	workload1 := &workloadapi.Workload{
		Locality: &workloadapi.Locality{
			Region:  "region1",
			Zone:    "zone1",
			Subzone: "subzone1",
		},
		Node:      "node1",
		Network:   "network1",
		ClusterId: "cluster1",
	}
	testCases := []struct {
		name     string
		wl       *workloadapi.Workload
		scopes   []workloadapi.LoadBalancing_Scope
		priority uint32
	}{
		{
			name: "match all scopes",
			wl:   workload1,
			scopes: []workloadapi.LoadBalancing_Scope{
				workloadapi.LoadBalancing_REGION,
				workloadapi.LoadBalancing_ZONE,
				workloadapi.LoadBalancing_SUBZONE,
				workloadapi.LoadBalancing_NODE,
				workloadapi.LoadBalancing_CLUSTER,
				workloadapi.LoadBalancing_NETWORK,
			},
			priority: 0,
		},
		{
			name: "match only region/zone/subzone",
			wl: &workloadapi.Workload{
				Locality: &workloadapi.Locality{
					Region:  "region1",
					Zone:    "zone1",
					Subzone: "subzone1",
				},
				Node:      "node2",
				Network:   "network2",
				ClusterId: "cluster2",
			},
			scopes: []workloadapi.LoadBalancing_Scope{
				workloadapi.LoadBalancing_REGION,
				workloadapi.LoadBalancing_ZONE,
				workloadapi.LoadBalancing_SUBZONE,
				workloadapi.LoadBalancing_NODE,
				workloadapi.LoadBalancing_CLUSTER,
				workloadapi.LoadBalancing_NETWORK,
			}, priority: 3,
		},
		{
			name: "match only first region/zone/subzone",
			wl: &workloadapi.Workload{
				Locality: &workloadapi.Locality{
					Region:  "region1",
					Zone:    "zone1",
					Subzone: "subzone1",
				},
				Node:      "node2",
				Network:   "network1",
				ClusterId: "cluster1",
			},
			scopes: []workloadapi.LoadBalancing_Scope{
				workloadapi.LoadBalancing_REGION,
				workloadapi.LoadBalancing_ZONE,
				workloadapi.LoadBalancing_SUBZONE,
				workloadapi.LoadBalancing_NODE,
				workloadapi.LoadBalancing_CLUSTER,
				workloadapi.LoadBalancing_NETWORK,
			}, priority: 3,
		},
		{
			name: "match first scope",
			wl: &workloadapi.Workload{
				Locality: &workloadapi.Locality{
					Region:  "region1",
					Zone:    "zone2",
					Subzone: "subzone2",
				},
				Node:      "node2",
				Network:   "network1",
				ClusterId: "cluster1",
			},
			scopes: []workloadapi.LoadBalancing_Scope{
				workloadapi.LoadBalancing_REGION,
				workloadapi.LoadBalancing_ZONE,
				workloadapi.LoadBalancing_SUBZONE,
				workloadapi.LoadBalancing_NODE,
				workloadapi.LoadBalancing_CLUSTER,
				workloadapi.LoadBalancing_NETWORK,
			},
			priority: 5,
		},
		{
			name: "first scope doesnot match",
			wl: &workloadapi.Workload{
				Locality: &workloadapi.Locality{
					Region:  "region2",
					Zone:    "zone1",
					Subzone: "subzone1",
				},
				Node:      "node1",
				Network:   "network1",
				ClusterId: "cluster1",
			},
			scopes: []workloadapi.LoadBalancing_Scope{
				workloadapi.LoadBalancing_REGION,
				workloadapi.LoadBalancing_ZONE,
				workloadapi.LoadBalancing_SUBZONE,
				workloadapi.LoadBalancing_NODE,
				workloadapi.LoadBalancing_CLUSTER,
				workloadapi.LoadBalancing_NETWORK,
			},
			priority: 6,
		},
		{
			name: "first 2 scope match",
			wl: &workloadapi.Workload{
				Locality: &workloadapi.Locality{
					Region:  "region1",
					Zone:    "zone2",
					Subzone: "subzone1",
				},
				Node:      "node1",
				Network:   "network1",
				ClusterId: "cluster1",
			},
			scopes: []workloadapi.LoadBalancing_Scope{
				workloadapi.LoadBalancing_NETWORK,
				workloadapi.LoadBalancing_REGION,
				workloadapi.LoadBalancing_ZONE,
				workloadapi.LoadBalancing_SUBZONE,
			},
			priority: 2,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := localityCache.CalcLocalityLBPrio(tc.wl, tc.scopes)
			assert.Equal(t, tc.priority, result)
		})
	}
}
