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

package telemetry

import (
	"context"
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

func TestCommonTrafficLabels2map(t *testing.T) {
	type args struct {
		labels interface{}
	}
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "normal commonTrafficLabels to map test",
			args: args{
				labels: workloadMetricLabels{
					reporter: "destination",

					sourceWorkload:               "sleep",
					sourceCanonicalService:       "sleep",
					sourceCanonicalRevision:      "latest",
					sourceWorkloadNamespace:      "ambient-demo",
					sourcePrincipal:              "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
					sourceApp:                    "sleep",
					sourceVersion:                "latest",
					sourceCluster:                "Kubernetes",
					destinationPodAddress:        "192.168.10.24",
					destinationPodNamespace:      "ambient-demo",
					destinationPodName:           "tcp-echo",
					destinationWorkload:          "tcp-echo",
					destinationCanonicalService:  "tcp-echo",
					destinationCanonicalRevision: "v1",
					destinationWorkloadNamespace: "ambient-demo",
					destinationPrincipal:         "spiffe://cluster.local/ns/ambient-demo/sa/default",
					destinationApp:               "tcp-echo",
					destinationVersion:           "v1",
					destinationCluster:           "Kubernetes",
					requestProtocol:              "tcp",
					responseFlags:                "-",
					connectionSecurityPolicy:     "mutual_tls",
				},
			},
			want: map[string]string{
				"reporter":                       "destination",
				"source_workload":                "sleep",
				"source_canonical_service":       "sleep",
				"source_canonical_revision":      "latest",
				"source_workload_namespace":      "ambient-demo",
				"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
				"source_app":                     "sleep",
				"source_version":                 "latest",
				"source_cluster":                 "Kubernetes",
				"destination_pod_address":        "192.168.10.24",
				"destination_pod_namespace":      "ambient-demo",
				"destination_pod_name":           "tcp-echo",
				"destination_workload":           "tcp-echo",
				"destination_canonical_service":  "tcp-echo",
				"destination_canonical_revision": "v1",
				"destination_workload_namespace": "ambient-demo",
				"destination_principal":          "spiffe://cluster.local/ns/ambient-demo/sa/default",
				"destination_app":                "tcp-echo",
				"destination_version":            "v1",
				"destination_cluster":            "Kubernetes",
				"request_protocol":               "tcp",
				"response_flags":                 "-",
				"connection_security_policy":     "mutual_tls",
			},
		},
		{
			name: "empty commonTrafficLabels to map test",
			args: args{
				labels: workloadMetricLabels{},
			},
			want: map[string]string{
				"reporter":                       "-",
				"source_workload":                "-",
				"source_canonical_service":       "-",
				"source_canonical_revision":      "-",
				"source_workload_namespace":      "-",
				"source_principal":               "-",
				"source_app":                     "-",
				"source_version":                 "-",
				"source_cluster":                 "-",
				"destination_pod_address":        "-",
				"destination_pod_namespace":      "-",
				"destination_pod_name":           "-",
				"destination_workload":           "-",
				"destination_canonical_service":  "-",
				"destination_canonical_revision": "-",
				"destination_workload_namespace": "-",
				"destination_principal":          "-",
				"destination_app":                "-",
				"destination_version":            "-",
				"destination_cluster":            "-",
				"request_protocol":               "-",
				"response_flags":                 "-",
				"connection_security_policy":     "-",
			},
		},
		{
			name: "Only some fields in the commonTrafficLabels have values",
			args: args{
				labels: workloadMetricLabels{
					reporter:            "source",
					sourceWorkload:      "sleep",
					destinationWorkload: "tcp-echo",
				},
			},
			want: map[string]string{
				"reporter":                       "source",
				"source_workload":                "sleep",
				"source_canonical_service":       "-",
				"source_canonical_revision":      "-",
				"source_workload_namespace":      "-",
				"source_principal":               "-",
				"source_app":                     "-",
				"source_version":                 "-",
				"source_cluster":                 "-",
				"destination_pod_address":        "-",
				"destination_pod_namespace":      "-",
				"destination_pod_name":           "-",
				"destination_workload":           "tcp-echo",
				"destination_canonical_service":  "-",
				"destination_canonical_revision": "-",
				"destination_workload_namespace": "-",
				"destination_principal":          "-",
				"destination_app":                "-",
				"destination_version":            "-",
				"destination_cluster":            "-",
				"request_protocol":               "-",
				"response_flags":                 "-",
				"connection_security_policy":     "-",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := struct2map(tt.args.labels); !reflect.DeepEqual(got, tt.want) {
				assert.Equal(t, tt.want, got)
				t.Errorf("struct2map() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildMetricsToPrometheus(t *testing.T) {
	metrics := []*prometheus.GaugeVec{
		tcpConnectionClosedInWorkload,
		tcpConnectionOpenedInWorkload,
		tcpReceivedBytesInWorkload,
		tcpSentBytesInWorkload,
	}

	type args struct {
		data   requestMetric
		labels workloadMetricLabels
	}
	tests := []struct {
		name string
		args args
		want []float64
	}{
		{
			name: "test build metrisc to Prometheus",
			args: args{
				data: requestMetric{
					src:           [4]uint32{183763210, 0, 0, 0},
					dst:           [4]uint32{183762951, 0, 0, 0},
					sentBytes:     0x0000003,
					receivedBytes: 0x0000004,
					state:         TCP_ESTABLISHED,
				},
				labels: workloadMetricLabels{
					reporter:                     "destination",
					sourceWorkload:               "sleep",
					sourceCanonicalService:       "sleep",
					sourceCanonicalRevision:      "latest",
					sourceWorkloadNamespace:      "ambient-demo",
					sourcePrincipal:              "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
					sourceApp:                    "sleep",
					sourceVersion:                "latest",
					sourceCluster:                "Kubernetes",
					destinationPodAddress:        "192.168.20.25",
					destinationPodNamespace:      "ambient-demo",
					destinationPodName:           "tcp-echo",
					destinationWorkload:          "tcp-echo",
					destinationCanonicalService:  "tcp-echo",
					destinationCanonicalRevision: "v1",
					destinationWorkloadNamespace: "ambient-demo",
					destinationPrincipal:         "spiffe://cluster.local/ns/ambient-demo/sa/default",
					destinationApp:               "tcp-echo",
					destinationVersion:           "v1",
					destinationCluster:           "Kubernetes",
					requestProtocol:              "tcp",
					responseFlags:                "-",
					connectionSecurityPolicy:     "mutual_tls",
				},
			},
			want: []float64{
				0,
				1,
				4,
				3,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			go RunPrometheusClient(ctx)
			buildWorkloadMetricsToPrometheus(tt.args.data, tt.args.labels)
			commonLabels := struct2map(tt.args.labels)
			for index, metric := range metrics {
				if gauge, err := metric.GetMetricWith(commonLabels); err != nil {
					t.Errorf("use labels to get %v failed", metric)
				} else {
					var m dto.Metric
					gauge.Write(&m)
					value := m.Gauge.Value
					assert.Equal(t, tt.want[index], *value)
				}
			}
			cancel()
		})
	}
}

func TestBuildWorkloadMetric(t *testing.T) {
	type args struct {
		dstWorkload *workloadapi.Workload
		srcWorkload *workloadapi.Workload
	}
	tests := []struct {
		name string
		args args
		want workloadMetricLabels
	}{
		{
			name: "normal capability test",
			args: args{
				dstWorkload: &workloadapi.Workload{
					Namespace:         "kmesh-system",
					Name:              "kmesh",
					WorkloadName:      "kmesh-daemon",
					CanonicalName:     "dstCanonical",
					CanonicalRevision: "dstVersion",
					ClusterId:         "Kubernetes",
					TrustDomain:       "cluster.local",
					ServiceAccount:    "default",
				},
				srcWorkload: &workloadapi.Workload{
					Namespace:         "kmesh-system",
					Name:              "kmesh",
					WorkloadName:      "kmesh-daemon",
					CanonicalName:     "srcCanonical",
					CanonicalRevision: "srcVersion",
					ClusterId:         "Kubernetes",
					TrustDomain:       "cluster.local",
					ServiceAccount:    "default",
				},
			},
			want: workloadMetricLabels{
				reporter:                     "-",
				sourceWorkload:               "kmesh-daemon",
				sourceCanonicalService:       "srcCanonical",
				sourceCanonicalRevision:      "srcVersion",
				sourceWorkloadNamespace:      "kmesh-system",
				sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
				sourceApp:                    "srcCanonical",
				sourceVersion:                "srcVersion",
				sourceCluster:                "Kubernetes",
				destinationPodAddress:        "-",
				destinationPodNamespace:      "kmesh-system",
				destinationPodName:           "kmesh",
				destinationWorkload:          "kmesh-daemon",
				destinationCanonicalService:  "dstCanonical",
				destinationCanonicalRevision: "dstVersion",
				destinationWorkloadNamespace: "kmesh-system",
				destinationPrincipal:         "spiffe://cluster.local/ns/kmesh-system/sa/default",
				destinationApp:               "dstCanonical",
				destinationVersion:           "dstVersion",
				destinationCluster:           "Kubernetes",
				requestProtocol:              "-",
				responseFlags:                "-",
				connectionSecurityPolicy:     "-",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualLabels := buildWorkloadMetric(tt.args.dstWorkload, tt.args.srcWorkload)
			expectMap := struct2map(tt.want)
			actualMap := struct2map(actualLabels)
			assert.Equal(t, expectMap, actualMap)
		})
	}
}

func TestMetricGetWorkloadByAddress(t *testing.T) {
	workload := &workloadapi.Workload{
		Name: "ut-workload",
		Uid:  "123456",
		Addresses: [][]byte{
			{192, 168, 224, 22},
		},
	}
	type args struct {
		address []byte
	}
	tests := []struct {
		name string
		args args
		want *workloadapi.Workload
	}{
		{
			name: "normal capability test",
			args: args{
				address: []byte{192, 168, 224, 22},
			},
			want: workload,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache: cache.NewWorkloadCache(),
			}
			m.workloadCache.AddWorkload(workload)
			if got, _ := m.getWorkloadByAddress(tt.args.address); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Metric.getWorkloadByAddress() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildworkloadMetric(t *testing.T) {
	dstWorkload := &workloadapi.Workload{
		Namespace:         "kmesh-system",
		Name:              "kmesh",
		WorkloadName:      "kmesh-daemon",
		CanonicalName:     "dstCanonical",
		CanonicalRevision: "dstVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Uid:               "123456",
		Addresses: [][]byte{
			{192, 168, 224, 22},
		},
	}
	srcWorkload := &workloadapi.Workload{
		Namespace:         "kmesh-system",
		Name:              "kmesh",
		WorkloadName:      "kmesh-daemon",
		CanonicalName:     "srcCanonical",
		CanonicalRevision: "srcVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Uid:               "654321",
		Addresses: [][]byte{
			{10, 19, 25, 31},
		},
	}
	type args struct {
		data *requestMetric
	}
	tests := []struct {
		name    string
		args    args
		want    workloadMetricLabels
		wantErr bool
	}{
		{
			name: "normal capability test",
			args: args{
				data: &requestMetric{
					src:           [4]uint32{521736970, 0, 0, 0},
					dst:           [4]uint32{383822016, 0, 0, 0},
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: workloadMetricLabels{
				sourceWorkload:               "kmesh-daemon",
				sourceCanonicalService:       "srcCanonical",
				sourceCanonicalRevision:      "srcVersion",
				sourceWorkloadNamespace:      "kmesh-system",
				sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
				sourceApp:                    "srcCanonical",
				sourceVersion:                "srcVersion",
				sourceCluster:                "Kubernetes",
				destinationPodAddress:        "192.168.224.22",
				destinationPodNamespace:      "kmesh-system",
				destinationPodName:           "kmesh",
				destinationWorkload:          "kmesh-daemon",
				destinationCanonicalService:  "dstCanonical",
				destinationCanonicalRevision: "dstVersion",
				destinationWorkloadNamespace: "kmesh-system",
				destinationPrincipal:         "spiffe://cluster.local/ns/kmesh-system/sa/default",
				destinationApp:               "dstCanonical",
				destinationVersion:           "dstVersion",
				destinationCluster:           "Kubernetes",
				requestProtocol:              "tcp",
				responseFlags:                "-",
				connectionSecurityPolicy:     "mutual_tls",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache: cache.NewWorkloadCache(),
			}
			m.workloadCache.AddWorkload(dstWorkload)
			m.workloadCache.AddWorkload(srcWorkload)
			got := m.buildWorkloadMetric(tt.args.data)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Metric.buildMetric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRestoreIPv4(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
		want []byte
	}{
		{
			name: "IPv4 data change",
			args: args{
				bytes: []byte{71, 0, 244, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
			want: []byte{71, 0, 244, 10},
		},
		{
			name: "IPv6 data change",
			args: args{
				bytes: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
			},
			want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := restoreIPv4(tt.args.bytes); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("restoreIPv4() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildServiceMetric(t *testing.T) {
	dstWorkload := &workloadapi.Workload{
		Namespace:         "kmesh-system",
		Name:              "kmesh",
		WorkloadName:      "kmesh-daemon",
		CanonicalName:     "dstCanonical",
		CanonicalRevision: "dstVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Uid:               "123456",
		Addresses: [][]byte{
			{192, 168, 224, 22},
		},
		Services: map[string]*workloadapi.PortList{
			"kmesh-system/kmesh.kmesh-system.svc.cluster.local": {
				Ports: []*workloadapi.Port{
					{
						TargetPort:  80,
						ServicePort: 8000,
					},
				},
			},
		},
	}
	srcWorkload := &workloadapi.Workload{
		Namespace:         "kmesh-system",
		Name:              "kmesh",
		WorkloadName:      "kmesh-daemon",
		CanonicalName:     "srcCanonical",
		CanonicalRevision: "srcVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Uid:               "654321",
		Addresses: [][]byte{
			{10, 19, 25, 31},
		},
	}
	type args struct {
		data *requestMetric
	}
	tests := []struct {
		name    string
		args    args
		want    serviceMetricLabels
		wantErr bool
	}{
		{
			name: "normal capability test",
			args: args{
				data: &requestMetric{
					src:           [4]uint32{521736970, 0, 0, 0},
					dst:           [4]uint32{383822016, 0, 0, 0},
					dstPort:       uint16(80),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: serviceMetricLabels{
				sourceWorkload:               "kmesh-daemon",
				sourceCanonicalService:       "srcCanonical",
				sourceCanonicalRevision:      "srcVersion",
				sourceWorkloadNamespace:      "kmesh-system",
				sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
				sourceApp:                    "srcCanonical",
				sourceVersion:                "srcVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "kmesh.kmesh-system.svc.cluster.local",
				destinationServiceNamespace:  "kmesh-system",
				destinationServiceName:       "kmesh.kmesh-system.svc.cluster.local",
				destinationWorkload:          "kmesh-daemon",
				destinationCanonicalService:  "dstCanonical",
				destinationCanonicalRevision: "dstVersion",
				destinationWorkloadNamespace: "kmesh-system",
				destinationPrincipal:         "spiffe://cluster.local/ns/kmesh-system/sa/default",
				destinationApp:               "dstCanonical",
				destinationVersion:           "dstVersion",
				destinationCluster:           "Kubernetes",
				requestProtocol:              "tcp",
				responseFlags:                "-",
				connectionSecurityPolicy:     "mutual_tls",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache: cache.NewWorkloadCache(),
			}
			m.workloadCache.AddWorkload(dstWorkload)
			m.workloadCache.AddWorkload(srcWorkload)
			got := m.buildServiceMetric(tt.args.data)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_buildServiceMetric(t *testing.T) {
	type args struct {
		dstWorkload *workloadapi.Workload
		srcWorkload *workloadapi.Workload
		dstPort     uint16
	}
	tests := []struct {
		name string
		args args
		want serviceMetricLabels
	}{
		{
			name: "normal capability test",
			args: args{
				dstWorkload: &workloadapi.Workload{
					Namespace:         "kmesh-system",
					Name:              "kmesh",
					WorkloadName:      "kmesh-daemon",
					CanonicalName:     "dstCanonical",
					CanonicalRevision: "dstVersion",
					ClusterId:         "Kubernetes",
					TrustDomain:       "cluster.local",
					ServiceAccount:    "default",
					Services: map[string]*workloadapi.PortList{
						"kmesh-system/kmesh": {
							Ports: []*workloadapi.Port{
								{
									ServicePort: 80,
									TargetPort:  8000,
								},
							},
						},
					},
				},
				srcWorkload: &workloadapi.Workload{
					Namespace:         "kmesh-system",
					Name:              "kmesh",
					WorkloadName:      "kmesh-daemon",
					CanonicalName:     "srcCanonical",
					CanonicalRevision: "srcVersion",
					ClusterId:         "Kubernetes",
					TrustDomain:       "cluster.local",
					ServiceAccount:    "default",
				},
				dstPort: uint16(8000),
			},
			want: serviceMetricLabels{
				reporter:                     "",
				sourceWorkload:               "kmesh-daemon",
				sourceCanonicalService:       "srcCanonical",
				sourceCanonicalRevision:      "srcVersion",
				sourceWorkloadNamespace:      "kmesh-system",
				sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
				sourceApp:                    "srcCanonical",
				sourceVersion:                "srcVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "kmesh",
				destinationServiceNamespace:  "kmesh-system",
				destinationServiceName:       "kmesh",
				destinationWorkload:          "kmesh-daemon",
				destinationCanonicalService:  "dstCanonical",
				destinationCanonicalRevision: "dstVersion",
				destinationWorkloadNamespace: "kmesh-system",
				destinationPrincipal:         "spiffe://cluster.local/ns/kmesh-system/sa/default",
				destinationApp:               "dstCanonical",
				destinationVersion:           "dstVersion",
				destinationCluster:           "Kubernetes",
				requestProtocol:              "",
				responseFlags:                "",
				connectionSecurityPolicy:     "",
			},
		},
		{
			name: "nil destination workload",
			args: args{
				dstWorkload: &workloadapi.Workload{},
				srcWorkload: &workloadapi.Workload{
					Namespace:         "kmesh-system",
					Name:              "kmesh",
					WorkloadName:      "kmesh-daemon",
					CanonicalName:     "srcCanonical",
					CanonicalRevision: "srcVersion",
					ClusterId:         "Kubernetes",
					TrustDomain:       "cluster.local",
					ServiceAccount:    "default",
				},
				dstPort: uint16(8000),
			},
			want: serviceMetricLabels{
				reporter:                     "",
				sourceWorkload:               "kmesh-daemon",
				sourceCanonicalService:       "srcCanonical",
				sourceCanonicalRevision:      "srcVersion",
				sourceWorkloadNamespace:      "kmesh-system",
				sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
				sourceApp:                    "srcCanonical",
				sourceVersion:                "srcVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "",
				destinationServiceNamespace:  "",
				destinationServiceName:       "",
				destinationWorkload:          "",
				destinationCanonicalService:  "",
				destinationCanonicalRevision: "",
				destinationWorkloadNamespace: "",
				destinationPrincipal:         "-",
				destinationApp:               "",
				destinationVersion:           "",
				destinationCluster:           "",
				requestProtocol:              "",
				responseFlags:                "",
				connectionSecurityPolicy:     "",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildServiceMetric(tt.args.dstWorkload, tt.args.srcWorkload, tt.args.dstPort)
			assert.Equal(t, tt.want, got)
		})
	}
}
