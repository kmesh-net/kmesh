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
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

func TestConvertServiceWaypoint(t *testing.T) {
	testcases := []struct {
		name     string
		waypoint *workloadapi.GatewayAddress
		expect   *Waypoint
	}{
		{
			name:     "no waypoint",
			waypoint: nil,
			expect:   nil,
		},
		{
			name: "waypoint by address",
			waypoint: &workloadapi.GatewayAddress{
				Destination: &workloadapi.GatewayAddress_Address{
					Address: &workloadapi.NetworkAddress{
						Network: "testnetwork",
						Address: net.ParseIP("192.168.1.10").To4(),
					},
				},
			},
			expect: &Waypoint{Destination: "testnetwork/192.168.1.10"},
		},
		{
			name: "waypoint by hostname",
			waypoint: &workloadapi.GatewayAddress{
				Destination: &workloadapi.GatewayAddress_Hostname{
					Hostname: &workloadapi.NamespacedHostname{
						Namespace: "default",
						Hostname:  "waypoint.default.svc.cluster.local",
					},
				},
			},
			expect: &Waypoint{Destination: "default/waypoint.default.svc.cluster.local"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			got := ConvertService(&workloadapi.Service{
				Name:      "productpage",
				Namespace: "default",
				Hostname:  "productpage.default.svc.cluster.local",
				Waypoint:  tc.waypoint,
			})
			assert.Equal(t, tc.expect, got.Waypoint)
		})
	}
}

// A service without a waypoint must serialise waypoint as null, the same way a
// service without load balancing already serialises loadBalancer as null.
// Otherwise a consumer cannot tell "no waypoint" apart from "waypoint whose
// destination happens to be empty".
func TestConvertServiceOmitsEmptyWaypointInJSON(t *testing.T) {
	got := ConvertService(&workloadapi.Service{
		Name:      "productpage",
		Namespace: "default",
		Hostname:  "productpage.default.svc.cluster.local",
		Addresses: []*workloadapi.NetworkAddress{
			{Network: "testnetwork", Address: net.ParseIP("10.96.0.21").To4()},
		},
	})

	data, err := json.Marshal(got)
	assert.NoError(t, err)

	var decoded map[string]interface{}
	assert.NoError(t, json.Unmarshal(data, &decoded))

	assert.Contains(t, decoded, "waypoint")
	assert.Nil(t, decoded["waypoint"])
	assert.Contains(t, decoded, "loadBalancer")
	assert.Nil(t, decoded["loadBalancer"])
}

func TestConvertServiceAddresses(t *testing.T) {
	got := ConvertService(&workloadapi.Service{
		Name:      "reviews",
		Namespace: "default",
		Hostname:  "reviews.default.svc.cluster.local",
		Addresses: []*workloadapi.NetworkAddress{
			{Network: "testnetwork", Address: net.ParseIP("10.96.0.22").To4()},
		},
		LoadBalancing: &workloadapi.LoadBalancing{
			Mode: workloadapi.LoadBalancing_FAILOVER,
			RoutingPreference: []workloadapi.LoadBalancing_Scope{
				workloadapi.LoadBalancing_NETWORK,
				workloadapi.LoadBalancing_REGION,
			},
		},
	})

	assert.Equal(t, []string{"testnetwork/10.96.0.22"}, got.Addresses)
	assert.Equal(t, &LoadBalancer{
		Mode:               "FAILOVER",
		RoutingPreferences: []string{"NETWORK", "REGION"},
	}, got.LoadBalancer)
}
