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

func Test_byteToFloat64(t *testing.T) {
	type args struct {
		bytes []byte
	}
	tests := []struct {
		name string
		args args
		want float64
	}{
		{
			name: "From byte to float64",
			args: args{
				bytes: []byte{34, 1, 0, 0},
			},
			want: float64(290),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := byteToFloat64(tt.args.bytes); got != tt.want {
				t.Errorf("byteToFloat64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCommonTrafficLabels2map(t *testing.T) {
	type args struct {
		labels *commonTrafficLabels
	}
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "normal commonTrafficLabels to map test",
			args: args{
				labels: &commonTrafficLabels{
					direction: "INBOUND",

					sourceWorkload:               "sleep",
					sourceCanonicalService:       "sleep",
					sourceCanonicalRevision:      "latest",
					sourceWorkloadNamespace:      "ambient-demo",
					sourcePrincipal:              "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
					sourceApp:                    "sleep",
					sourceVersion:                "latest",
					sourceCluster:                "Kubernetes",
					destinationService:           "tcp-echo.ambient-demo.svc.cluster.local",
					destinationServiceNamespace:  "ambient-demo",
					destinationServiceName:       "tcp-echo",
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
				"direction":                      "INBOUND",
				"source_workload":                "sleep",
				"source_canonical_service":       "sleep",
				"source_canonical_revision":      "latest",
				"source_workload_namespace":      "ambient-demo",
				"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
				"source_app":                     "sleep",
				"source_version":                 "latest",
				"source_cluster":                 "Kubernetes",
				"destination_service":            "tcp-echo.ambient-demo.svc.cluster.local",
				"destination_service_namespace":  "ambient-demo",
				"destination_service_name":       "tcp-echo",
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
				labels: &commonTrafficLabels{},
			},
			want: map[string]string{
				"direction":                      "-",
				"source_workload":                "-",
				"source_canonical_service":       "-",
				"source_canonical_revision":      "-",
				"source_workload_namespace":      "-",
				"source_principal":               "-",
				"source_app":                     "-",
				"source_version":                 "-",
				"source_cluster":                 "-",
				"destination_service":            "-",
				"destination_service_namespace":  "-",
				"destination_service_name":       "-",
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
				labels: &commonTrafficLabels{
					direction:           "OUTBOUND",
					sourceWorkload:      "sleep",
					destinationWorkload: "tcp-echo",
				},
			},
			want: map[string]string{
				"direction":                      "OUTBOUND",
				"source_workload":                "sleep",
				"source_canonical_service":       "-",
				"source_canonical_revision":      "-",
				"source_workload_namespace":      "-",
				"source_principal":               "-",
				"source_app":                     "-",
				"source_version":                 "-",
				"source_cluster":                 "-",
				"destination_service":            "-",
				"destination_service_namespace":  "-",
				"destination_service_name":       "-",
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
			if got := commonTrafficLabels2map(tt.args.labels); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("commonTrafficLabels2map() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildMetricsToPrometheus(t *testing.T) {
	metrics := []*prometheus.GaugeVec{
		tcpConnectionClosed,
		tcpConnectionOpened,
		tcpReceivedBytes,
		tcpSentBytes,
	}

	type args struct {
		data   requestMetric
		labels commonTrafficLabels
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
					src:              [4]uint32{183763210, 0, 0, 0},
					dst:              [4]uint32{183762951, 0, 0, 0},
					connectionOpened: 0x0000001,
					connectionClosed: 0x0000002,
					sentBytes:        0x0000003,
					receivedBytes:    0x0000004,
					success:          true,
				},
				labels: commonTrafficLabels{
					direction:                    "INBOUND",
					sourceWorkload:               "sleep",
					sourceCanonicalService:       "sleep",
					sourceCanonicalRevision:      "latest",
					sourceWorkloadNamespace:      "ambient-demo",
					sourcePrincipal:              "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
					sourceApp:                    "sleep",
					sourceVersion:                "latest",
					sourceCluster:                "Kubernetes",
					destinationService:           "tcp-echo.ambient-demo.svc.cluster.local",
					destinationServiceNamespace:  "ambient-demo",
					destinationServiceName:       "tcp-echo",
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
				2,
				1,
				4,
				3,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					default:
						RunPrometheusClient()
					}
				}
			}()
			buildMetricsToPrometheus(tt.args.data, tt.args.labels)
			commonLabels := commonTrafficLabels2map(&tt.args.labels)
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

func TestBuildMetricFromWorkload(t *testing.T) {
	type args struct {
		dstWorkload *workloadapi.Workload
		srcWorkload *workloadapi.Workload
	}
	tests := []struct {
		name string
		args args
		want commonTrafficLabels
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
			want: commonTrafficLabels{
				direction:                    "-",
				sourceWorkload:               "kmesh-daemon",
				sourceCanonicalService:       "srcCanonical",
				sourceCanonicalRevision:      "srcVersion",
				sourceWorkloadNamespace:      "kmesh-system",
				sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
				sourceApp:                    "srcCanonical",
				sourceVersion:                "srcVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "-",
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
				requestProtocol:              "-",
				responseFlags:                "-",
				connectionSecurityPolicy:     "-",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualLabels := buildMetricFromWorkload(tt.args.dstWorkload, tt.args.srcWorkload)
			expectMap := commonTrafficLabels2map(&tt.want)
			actualMap := commonTrafficLabels2map(&actualLabels)
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

func TestMetricBuildMetric(t *testing.T) {
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
		want    commonTrafficLabels
		wantErr bool
	}{
		{
			name: "normal capability test",
			args: args{
				data: &requestMetric{
					src:              [4]uint32{521736970, 0, 0, 0},
					dst:              [4]uint32{383822016, 0, 0, 0},
					connectionOpened: uint32(16),
					connectionClosed: uint32(8),
					sentBytes:        uint32(156),
					receivedBytes:    uint32(1024),
					success:          true,
				},
			},
			want: commonTrafficLabels{
				sourceWorkload:               "kmesh-daemon",
				sourceCanonicalService:       "srcCanonical",
				sourceCanonicalRevision:      "srcVersion",
				sourceWorkloadNamespace:      "kmesh-system",
				sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
				sourceApp:                    "srcCanonical",
				sourceVersion:                "srcVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "192.168.224.22",
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
			got, err := m.buildMetric(tt.args.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Metric.buildMetric() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Metric.buildMetric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestByteToIpByte(t *testing.T) {
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
