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
	"os"
	"os/exec"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	dnsproto "istio.io/istio/pkg/dns/proto"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

func TestBuildNameTable(t *testing.T) {
	type TestCase struct {
		name      string
		services  []*workloadapi.Service
		workloads []*workloadapi.Workload
		want      *dnsproto.NameTable
	}

	testCases := []TestCase{
		{
			name: "Common kubernetes service test",
			services: []*workloadapi.Service{
				{
					Name:      "svc1",
					Namespace: "ns1",
					Hostname:  "svc1.ns1.svc.cluster.local",
					Addresses: []*workloadapi.NetworkAddress{
						{
							Address: []byte{10, 0, 0, 1},
						},
					},
				},
			},
			want: &dnsproto.NameTable{
				Table: map[string]*dnsproto.NameTable_NameInfo{
					"svc1.ns1.svc.cluster.local": {
						Ips:       []string{"10.0.0.1"},
						Registry:  "Kubernetes",
						Namespace: "ns1",
						Shortname: "svc1",
					},
				},
			},
		},
		{
			name: "Headless service test",
			services: []*workloadapi.Service{
				{
					Name:      "svc1",
					Namespace: "ns1",
					Hostname:  "svc1.ns1.svc.cluster.local",
				},
			},
			workloads: []*workloadapi.Workload{
				{
					Name:      "workload1",
					Namespace: "ns1",
					Addresses: [][]byte{
						{
							10, 0, 0, 1,
						},
					},
					Services: map[string]*workloadapi.PortList{
						"ns1/svc1.ns1.svc.cluster.local": {
							Ports: []*workloadapi.Port{
								{
									ServicePort: 80,
								},
							},
						},
					},
				},
			},
			want: &dnsproto.NameTable{
				Table: map[string]*dnsproto.NameTable_NameInfo{
					"svc1.ns1.svc.cluster.local": {
						Ips:       []string{"10.0.0.1"},
						Registry:  "Kubernetes",
						Namespace: "ns1",
						Shortname: "svc1",
					},
				},
			},
		},
		{
			name: "ServiceEntry test",
			services: []*workloadapi.Service{
				{
					Name:      "svc1",
					Namespace: "ns1",
					Hostname:  "kmesh-fake.com",
					Addresses: []*workloadapi.NetworkAddress{
						{
							Address: []byte{240, 0, 0, 1},
						},
					},
				},
			},
			want: &dnsproto.NameTable{
				Table: map[string]*dnsproto.NameTable_NameInfo{
					"kmesh-fake.com": {
						Ips:      []string{"240.0.0.1"},
						Registry: "External",
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			serviceCache := cache.NewServiceCache()
			workloadCache := cache.NewWorkloadCache()

			for _, svc := range tc.services {
				serviceCache.AddOrUpdateService(svc)
			}

			for _, workload := range tc.workloads {
				workloadCache.AddOrUpdateWorkload(workload)
			}

			ntb := NewNameTableBuilder(serviceCache, workloadCache)
			got := ntb.BuildNameTable()
			if diff := cmp.Diff(got, tc.want, protocmp.Transform()); diff != "" {
				t.Fatalf("got diff: %v", diff)
			}
		})
	}
}

// Run with CLUSTER_DOMAIN set before process startup to exercise the same
// environment configuration used by the daemon's DNS server and name table.
func TestBuildNameTableConfiguredClusterDomain(t *testing.T) {
	// clusterDomain is read during package initialization, so each environment
	// must be tested in a fresh process rather than changed with t.Setenv alone.
	if os.Getenv("KMESH_TEST_CLUSTER_DOMAIN") != "1" {
		for _, domain := range []string{"cluster.local", "corp.internal"} {
			t.Run(domain, func(t *testing.T) {
				t.Setenv("CLUSTER_DOMAIN", domain)
				t.Setenv("KMESH_TEST_CLUSTER_DOMAIN", "1")
				cmd := exec.Command(os.Args[0], "-test.run=^TestBuildNameTableConfiguredClusterDomain$")
				if output, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("name table with domain %s: %v\n%s", domain, err, output)
				}
			})
		}
		return
	}
	domain := os.Getenv("CLUSTER_DOMAIN")
	serviceCache := cache.NewServiceCache()
	hostname := "svc1.ns1.svc." + domain
	serviceCache.AddOrUpdateService(&workloadapi.Service{
		Name:      "svc1",
		Namespace: "ns1",
		Hostname:  hostname,
		Addresses: []*workloadapi.NetworkAddress{{Address: []byte{10, 0, 0, 1}}},
	})
	got := NewNameTableBuilder(serviceCache, cache.NewWorkloadCache()).BuildNameTable()
	want := &dnsproto.NameTable{
		Table: map[string]*dnsproto.NameTable_NameInfo{
			hostname: {
				Ips:       []string{"10.0.0.1"},
				Registry:  "Kubernetes",
				Namespace: "ns1",
				Shortname: "svc1",
			},
		},
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("unexpected name table (-want +got): %s", diff)
	}
}
