package dns

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	dnsProto "istio.io/istio/pkg/dns/proto"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

func TestBuildNameTable(t *testing.T) {
	type TestCase struct {
		name      string
		services  []*workloadapi.Service
		workloads []*workloadapi.Workload
		want      *dnsProto.NameTable
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
			want: &dnsProto.NameTable{
				Table: map[string]*dnsProto.NameTable_NameInfo{
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
			want: &dnsProto.NameTable{
				Table: map[string]*dnsProto.NameTable_NameInfo{
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
			want: &dnsProto.NameTable{
				Table: map[string]*dnsProto.NameTable_NameInfo{
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
