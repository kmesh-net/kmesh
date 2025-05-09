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
	"bytes"
	"context"
	"net"
	"reflect"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/nets"
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
	type args struct {
		data     requestMetric
		labels   workloadMetricLabels
		tcpConns map[connectionSrcDst]connMetric
	}
	tests := []struct {
		name string
		args args
		want []float64
	}{
		{
			name: "test build workload metrics to metricCache",
			args: args{
				data: requestMetric{
					conSrcDstInfo: connectionSrcDst{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					},
					sentBytes:     0x0000003,
					receivedBytes: 0x0000004,
					packetLost:    0x0000001,
					totalRetrans:  0x0000002,
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
				tcpConns: map[connectionSrcDst]connMetric{
					{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					}: {
						totalReports: 1,
					},
				},
			},
			want: []float64{
				0,
				1,
				4,
				3,
				1,
				2,
			},
		},
		{
			name: "test build workload metrics in metricCache for conn report at intervals",
			args: args{
				data: requestMetric{
					conSrcDstInfo: connectionSrcDst{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					},
					sentBytes:     0x0000003,
					receivedBytes: 0x0000004,
					packetLost:    0x0000001,
					totalRetrans:  0x0000002,
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
				tcpConns: map[connectionSrcDst]connMetric{
					{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					}: {
						totalReports: 3,
					},
				},
			},
			want: []float64{
				0,
				0,
				4,
				3,
				1,
				2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache:       cache.NewWorkloadCache(),
				workloadMetricCache: map[workloadMetricLabels]*workloadMetricInfo{},
				serviceMetricCache:  map[serviceMetricLabels]*serviceMetricInfo{},
			}
			m.updateWorkloadMetricCache(tt.args.data, tt.args.labels, tt.args.tcpConns[tt.args.data.conSrcDstInfo])
			assert.Equal(t, m.workloadMetricCache[tt.args.labels].WorkloadConnClosed, tt.want[0])
			assert.Equal(t, m.workloadMetricCache[tt.args.labels].WorkloadConnOpened, tt.want[1])
			assert.Equal(t, m.workloadMetricCache[tt.args.labels].WorkloadConnReceivedBytes, tt.want[2])
			assert.Equal(t, m.workloadMetricCache[tt.args.labels].WorkloadConnSentBytes, tt.want[3])
			assert.Equal(t, m.workloadMetricCache[tt.args.labels].WorkloadConnPacketLost, tt.want[4])
			assert.Equal(t, m.workloadMetricCache[tt.args.labels].WorkloadConnTotalRetrans, tt.want[5])
		})
	}
}

func TestBuildServiceMetricsToPrometheus(t *testing.T) {
	type args struct {
		data     requestMetric
		labels   serviceMetricLabels
		tcpConns map[connectionSrcDst]connMetric
	}
	tests := []struct {
		name string
		args args
		want []float64
	}{
		{
			name: "build service metrics in metricCache",
			args: args{
				data: requestMetric{
					conSrcDstInfo: connectionSrcDst{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					},
					sentBytes:     0x0000009,
					receivedBytes: 0x0000008,
					state:         TCP_ESTABLISHED,
				},
				labels: serviceMetricLabels{
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
				tcpConns: map[connectionSrcDst]connMetric{
					{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					}: {
						totalReports: 1,
					},
				},
			},
			want: []float64{
				0,
				1,
				8,
				9,
			},
		},
		{
			name: "build service metrics in metricCache for conn report at interval",
			args: args{
				data: requestMetric{
					conSrcDstInfo: connectionSrcDst{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					},
					sentBytes:     0x0000009,
					receivedBytes: 0x0000008,
					state:         TCP_ESTABLISHED,
				},
				labels: serviceMetricLabels{
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
				tcpConns: map[connectionSrcDst]connMetric{
					{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					}: {
						totalReports: 3,
					},
				},
			},
			want: []float64{
				0,
				0,
				8,
				9,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache:       cache.NewWorkloadCache(),
				workloadMetricCache: map[workloadMetricLabels]*workloadMetricInfo{},
				serviceMetricCache:  map[serviceMetricLabels]*serviceMetricInfo{},
			}
			m.updateServiceMetricCache(tt.args.data, tt.args.labels, tt.args.tcpConns[tt.args.data.conSrcDstInfo])
			assert.Equal(t, m.serviceMetricCache[tt.args.labels].ServiceConnClosed, tt.want[0])
			assert.Equal(t, m.serviceMetricCache[tt.args.labels].ServiceConnOpened, tt.want[1])
			assert.Equal(t, m.serviceMetricCache[tt.args.labels].ServiceConnReceivedBytes, tt.want[2])
			assert.Equal(t, m.serviceMetricCache[tt.args.labels].ServiceConnSentBytes, tt.want[3])
		})
	}
}

func TestBuildConnectionMetricsToPrometheus(t *testing.T) {
	type args struct {
		data     requestMetric
		labels   connectionMetricLabels
		tcpConns map[connectionSrcDst]connMetric
	}
	tests := []struct {
		id   int32
		name string
		args args
		want []float64
	}{
		{
			id:   int32(1),
			name: "test build connection metric to metricCache",
			args: args{
				data: requestMetric{
					conSrcDstInfo: connectionSrcDst{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					},
					sentBytes:     0x0000003,
					receivedBytes: 0x0000004,
					packetLost:    0x0000001,
					totalRetrans:  0x0000002,
					state:         TCP_ESTABLISHED,
				},
				labels: connectionMetricLabels{
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
				tcpConns: map[connectionSrcDst]connMetric{
					{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					}: {
						sentBytes:     0x0000003,
						receivedBytes: 0x0000004,
						packetLost:    0x0000001,
						totalRetrans:  0x0000002,
						totalReports:  1,
					},
				},
			},
			want: []float64{
				3,
				4,
				1,
				2,
			},
		},
		{
			id:   int32(2),
			name: "test build workload metrisc to metricCache for conn report at intervals",
			args: args{
				data: requestMetric{
					conSrcDstInfo: connectionSrcDst{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					},
					sentBytes:     0x0000003,
					receivedBytes: 0x0000004,
					packetLost:    0x0000001,
					totalRetrans:  0x0000002,
					state:         TCP_CLOSED,
				},
				labels: connectionMetricLabels{
					reporter:                     "source",
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
				tcpConns: map[connectionSrcDst]connMetric{
					{
						src: [4]uint32{183763210, 0, 0, 0},
						dst: [4]uint32{183762951, 0, 0, 0},
					}: {
						totalReports: 3,
					},
				},
			},
			want: []float64{
				4,
				5,
				2,
				3,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache:       cache.NewWorkloadCache(),
				workloadMetricCache: map[workloadMetricLabels]*workloadMetricInfo{},
				serviceMetricCache:  map[serviceMetricLabels]*serviceMetricInfo{},
				connectionMetricCache: map[connectionMetricLabels]*connectionMetricInfo{
					{
						reporter:                     "source",
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
					}: {
						ConnSentBytes:     0x0000001,
						ConnReceivedBytes: 0x0000001,
						ConnPacketLost:    0x0000001,
						ConnTotalRetrans:  0x0000001,
					},
				},
			}

			deleteConnection = []*connectionMetricLabels{}
			m.updateConnectionMetricCache(tt.args.data, tt.args.tcpConns[tt.args.data.conSrcDstInfo], tt.args.labels)
			assert.Equal(t, m.connectionMetricCache[tt.args.labels].ConnSentBytes, tt.want[0])
			assert.Equal(t, m.connectionMetricCache[tt.args.labels].ConnReceivedBytes, tt.want[1])
			assert.Equal(t, m.connectionMetricCache[tt.args.labels].ConnPacketLost, tt.want[2])
			assert.Equal(t, m.connectionMetricCache[tt.args.labels].ConnTotalRetrans, tt.want[3])
			if tt.id == 1 {
				assert.Equal(t, len(deleteConnection), 0)
			} else {
				assert.Equal(t, len(deleteConnection), 1)
			}
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
			m.workloadCache.AddOrUpdateWorkload(workload)
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
					conSrcDstInfo: connectionSrcDst{
						src: [4]uint32{521736970, 0, 0, 0},
						dst: [4]uint32{383822016, 0, 0, 0},
					},
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
					packetLost:    uint32(5),
					totalRetrans:  uint32(120),
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
				responseFlags:                "",
				connectionSecurityPolicy:     "mutual_tls",
				reporter:                     "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache: cache.NewWorkloadCache(),
			}
			m.workloadCache.AddOrUpdateWorkload(dstWorkload)
			m.workloadCache.AddOrUpdateWorkload(srcWorkload)
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
	type args struct {
		data *requestMetric
	}
	serviceCache := cache.NewServiceCache()
	serviceCache.AddOrUpdateService(&workloadapi.Service{
		Hostname:  "kmesh.kmesh-system.svc.cluster.local",
		Namespace: "kmesh-system",
		Name:      "kmesh",
		Addresses: []*workloadapi.NetworkAddress{
			{
				Address: net.ParseIP("192.168.1.22").To4(),
			},
		},
	})
	serviceCache.AddOrUpdateService(&workloadapi.Service{
		Hostname:  "httpbin.default.svc.cluster.local",
		Namespace: "default",
		Name:      "httpbin",
		Addresses: []*workloadapi.NetworkAddress{
			{
				Address: net.ParseIP("192.168.1.23").To4(),
			},
		},
	})

	workloadCache := cache.NewWorkloadCache()

	workloadCache.AddOrUpdateWorkload(&workloadapi.Workload{
		Namespace:         "default",
		Name:              "sleep",
		WorkloadName:      "sleep",
		CanonicalName:     "sleepCanonical",
		CanonicalRevision: "sleepVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Addresses: [][]byte{
			{10, 19, 25, 33},
		},
	})

	// kmesh workload with service attached
	workloadCache.AddOrUpdateWorkload(&workloadapi.Workload{
		Namespace:         "kmesh-system",
		Name:              "kmesh",
		WorkloadName:      "kmesh-daemon",
		CanonicalName:     "dstCanonical",
		CanonicalRevision: "dstVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Services: map[string]*workloadapi.PortList{
			"kmesh-system/kmesh.kmesh-system.svc.cluster.local": {
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8000,
					},
				},
			},
		},
		Addresses: [][]byte{
			{10, 19, 25, 31},
		},
	})

	// a solely workload without service attached
	workloadCache.AddOrUpdateWorkload(&workloadapi.Workload{
		Namespace:         "default",
		Name:              "solelyWorkload",
		WorkloadName:      "solelyWorkload",
		CanonicalName:     "solelyCanonical",
		CanonicalRevision: "solelyVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Addresses: [][]byte{
			{10, 19, 25, 34},
		},
	})

	workloadCache.AddOrUpdateWorkload(&workloadapi.Workload{
		Namespace:         "default",
		Name:              "waypoint",
		WorkloadName:      "waypoint",
		CanonicalName:     "waypointCanonical",
		CanonicalRevision: "waypointVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Addresses: [][]byte{
			{10, 19, 25, 32},
		},
	})

	m := MetricController{
		workloadCache: workloadCache,
		serviceCache:  serviceCache,
	}
	tests := []struct {
		name        string
		args        args
		want        serviceMetricLabels
		wantLogInfo logInfo
	}{
		{
			name: "destination exists with service attached, workload-type request",
			args: args{
				data: &requestMetric{
					conSrcDstInfo: connectionSrcDst{
						// sleep
						src: [4]uint32{nets.ConvertIpToUint32("10.19.25.33"), 0, 0, 0},
						// kmesh-daemon
						dst:     [4]uint32{nets.ConvertIpToUint32("10.19.25.31"), 0, 0, 0},
						dstPort: uint16(8000),
						srcPort: uint16(8000),
					},
					// kmesh-daemon
					origDstAddr:   [4]uint32{nets.ConvertIpToUint32("10.19.25.31"), 0, 0, 0},
					origDstPort:   uint16(8000),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: serviceMetricLabels{
				sourceWorkload:               "sleep",
				sourceCanonicalService:       "sleepCanonical",
				sourceCanonicalRevision:      "sleepVersion",
				sourceWorkloadNamespace:      "default",
				sourcePrincipal:              "spiffe://cluster.local/ns/default/sa/default",
				sourceApp:                    "sleepCanonical",
				sourceVersion:                "sleepVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "kmesh.kmesh-system.svc.cluster.local",
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
				responseFlags:                "",
				connectionSecurityPolicy:     "mutual_tls",
				reporter:                     "source",
			},
			wantLogInfo: logInfo{
				direction:            "OUTBOUND",
				sourceAddress:        "10.19.25.33:8000",
				sourceWorkload:       "sleep",
				sourceNamespace:      "default",
				destinationAddress:   "10.19.25.31:8000",
				destinationService:   "kmesh.kmesh-system.svc.cluster.local",
				destinationWorkload:  "kmesh",
				destinationNamespace: "kmesh-system",
			},
		},
		{
			name: "destination exists with service attached, service-type request",
			args: args{
				data: &requestMetric{
					conSrcDstInfo: connectionSrcDst{
						// sleep
						src: [4]uint32{nets.ConvertIpToUint32("10.19.25.33"), 0, 0, 0},
						// kmesh-daemon
						dst:     [4]uint32{nets.ConvertIpToUint32("10.19.25.31"), 0, 0, 0},
						dstPort: uint16(8000),
						srcPort: uint16(8000),
					},
					// kmesh-daemon
					origDstAddr:   [4]uint32{nets.ConvertIpToUint32("192.168.1.22"), 0, 0, 0},
					origDstPort:   uint16(8000),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: serviceMetricLabels{
				sourceWorkload:               "sleep",
				sourceCanonicalService:       "sleepCanonical",
				sourceCanonicalRevision:      "sleepVersion",
				sourceWorkloadNamespace:      "default",
				sourcePrincipal:              "spiffe://cluster.local/ns/default/sa/default",
				sourceApp:                    "sleepCanonical",
				sourceVersion:                "sleepVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "kmesh.kmesh-system.svc.cluster.local",
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
				responseFlags:                "",
				connectionSecurityPolicy:     "mutual_tls",
				reporter:                     "source",
			},
			wantLogInfo: logInfo{
				direction:            "OUTBOUND",
				sourceAddress:        "10.19.25.33:8000",
				sourceWorkload:       "sleep",
				sourceNamespace:      "default",
				destinationAddress:   "10.19.25.31:8000",
				destinationService:   "kmesh.kmesh-system.svc.cluster.local",
				destinationWorkload:  "kmesh",
				destinationNamespace: "kmesh-system",
			},
		},
		{
			name: "nil destination workload",
			args: args{
				data: &requestMetric{
					conSrcDstInfo: connectionSrcDst{
						// sleep
						src: [4]uint32{nets.ConvertIpToUint32("10.19.25.33"), 0, 0, 0},
						// unknown address
						dst:     [4]uint32{nets.ConvertIpToUint32("191.168.224.22"), 0, 0, 0},
						dstPort: uint16(80),
						srcPort: uint16(8000),
					},
					// unknown address
					origDstAddr:   [4]uint32{nets.ConvertIpToUint32("191.168.224.22"), 0, 0, 0},
					origDstPort:   uint16(80),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: serviceMetricLabels{
				sourceWorkload:               "sleep",
				sourceCanonicalService:       "sleepCanonical",
				sourceCanonicalRevision:      "sleepVersion",
				sourceWorkloadNamespace:      "default",
				sourcePrincipal:              "spiffe://cluster.local/ns/default/sa/default",
				sourceApp:                    "sleepCanonical",
				sourceVersion:                "sleepVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "191.168.224.22",
				destinationServiceNamespace:  "",
				destinationServiceName:       "",
				destinationWorkload:          "",
				destinationCanonicalService:  "",
				destinationCanonicalRevision: "",
				destinationWorkloadNamespace: "",
				destinationPrincipal:         "",
				destinationApp:               "",
				destinationVersion:           "",
				destinationCluster:           "",
				requestProtocol:              "tcp",
				responseFlags:                "",
				connectionSecurityPolicy:     "mutual_tls",
				reporter:                     "source",
			},
			wantLogInfo: logInfo{
				direction:            "OUTBOUND",
				sourceAddress:        "10.19.25.33:8000",
				sourceWorkload:       "sleep",
				sourceNamespace:      "default",
				destinationAddress:   "191.168.224.22:80",
				destinationService:   "191.168.224.22",
				destinationWorkload:  "-",
				destinationNamespace: "-",
			},
		},
		{
			name: "service-type request, redirected to waypoint",
			args: args{
				data: &requestMetric{
					conSrcDstInfo: connectionSrcDst{
						// sleep
						src:     [4]uint32{nets.ConvertIpToUint32("10.19.25.33"), 0, 0, 0},
						srcPort: uint16(49875),
						// waypoint
						dst:     [4]uint32{nets.ConvertIpToUint32("10.19.25.32"), 0, 0, 0},
						dstPort: uint16(80),
					},
					// httpbin service
					origDstAddr:   [4]uint32{nets.ConvertIpToUint32("192.168.1.23"), 0, 0, 0},
					origDstPort:   uint16(80),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: serviceMetricLabels{
				sourceWorkload:               "sleep",
				sourceCanonicalService:       "sleepCanonical",
				sourceCanonicalRevision:      "sleepVersion",
				sourceWorkloadNamespace:      "default",
				sourcePrincipal:              "spiffe://cluster.local/ns/default/sa/default",
				sourceApp:                    "sleepCanonical",
				sourceVersion:                "sleepVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "httpbin.default.svc.cluster.local",
				destinationServiceNamespace:  "default",
				destinationServiceName:       "httpbin",
				destinationWorkload:          "waypoint",
				destinationCanonicalService:  "waypointCanonical",
				destinationCanonicalRevision: "waypointVersion",
				destinationWorkloadNamespace: "default",
				destinationPrincipal:         "spiffe://cluster.local/ns/default/sa/default",
				destinationApp:               "waypointCanonical",
				destinationVersion:           "waypointVersion",
				destinationCluster:           "Kubernetes",
				requestProtocol:              "tcp",
				responseFlags:                "",
				connectionSecurityPolicy:     "mutual_tls",
				reporter:                     "source",
			},
			wantLogInfo: logInfo{
				direction:            "OUTBOUND",
				sourceAddress:        "10.19.25.33:49875",
				sourceWorkload:       "sleep",
				sourceNamespace:      "default",
				destinationAddress:   "10.19.25.32:80",
				destinationService:   "httpbin.default.svc.cluster.local",
				destinationWorkload:  "waypoint",
				destinationNamespace: "default",
			},
		},
		{
			name: "workload-type request, redirected to waypoint",
			args: args{
				data: &requestMetric{
					conSrcDstInfo: connectionSrcDst{
						// sleep
						src:     [4]uint32{nets.ConvertIpToUint32("10.19.25.33"), 0, 0, 0},
						srcPort: uint16(49875),
						// waypoint
						dst:     [4]uint32{nets.ConvertIpToUint32("10.19.25.32"), 0, 0, 0},
						dstPort: uint16(80),
					},
					// solelyWorkload
					origDstAddr:   [4]uint32{nets.ConvertIpToUint32("10.19.25.34"), 0, 0, 0},
					origDstPort:   uint16(80),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: serviceMetricLabels{
				sourceWorkload:               "sleep",
				sourceCanonicalService:       "sleepCanonical",
				sourceCanonicalRevision:      "sleepVersion",
				sourceWorkloadNamespace:      "default",
				sourcePrincipal:              "spiffe://cluster.local/ns/default/sa/default",
				sourceApp:                    "sleepCanonical",
				sourceVersion:                "sleepVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "10.19.25.34",
				destinationServiceNamespace:  "default",
				destinationServiceName:       "",
				destinationWorkload:          "waypoint",
				destinationCanonicalService:  "waypointCanonical",
				destinationCanonicalRevision: "waypointVersion",
				destinationWorkloadNamespace: "default",
				destinationPrincipal:         "spiffe://cluster.local/ns/default/sa/default",
				destinationApp:               "waypointCanonical",
				destinationVersion:           "waypointVersion",
				destinationCluster:           "Kubernetes",
				requestProtocol:              "tcp",
				responseFlags:                "",
				connectionSecurityPolicy:     "mutual_tls",
				reporter:                     "source",
			},
			wantLogInfo: logInfo{
				direction:            "OUTBOUND",
				sourceAddress:        "10.19.25.33:49875",
				sourceWorkload:       "sleep",
				sourceNamespace:      "default",
				destinationAddress:   "10.19.25.32:80",
				destinationService:   "10.19.25.34",
				destinationWorkload:  "waypoint",
				destinationNamespace: "default",
			},
		},
		{
			name: "destination workload exists without service attached",
			args: args{
				data: &requestMetric{
					conSrcDstInfo: connectionSrcDst{
						// sleep
						src:     [4]uint32{nets.ConvertIpToUint32("10.19.25.33"), 0, 0, 0},
						srcPort: uint16(49875),
						// solely workload
						dst:     [4]uint32{nets.ConvertIpToUint32("10.19.25.34"), 0, 0, 0},
						dstPort: uint16(80),
					},
					// httpbin service
					origDstAddr:   [4]uint32{nets.ConvertIpToUint32("10.19.25.34"), 0, 0, 0},
					origDstPort:   uint16(80),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: serviceMetricLabels{
				sourceWorkload:               "sleep",
				sourceCanonicalService:       "sleepCanonical",
				sourceCanonicalRevision:      "sleepVersion",
				sourceWorkloadNamespace:      "default",
				sourcePrincipal:              "spiffe://cluster.local/ns/default/sa/default",
				sourceApp:                    "sleepCanonical",
				sourceVersion:                "sleepVersion",
				sourceCluster:                "Kubernetes",
				destinationService:           "10.19.25.34",
				destinationServiceNamespace:  "default",
				destinationServiceName:       "",
				destinationWorkload:          "solelyWorkload",
				destinationCanonicalService:  "solelyCanonical",
				destinationCanonicalRevision: "solelyVersion",
				destinationWorkloadNamespace: "default",
				destinationPrincipal:         "spiffe://cluster.local/ns/default/sa/default",
				destinationApp:               "solelyCanonical",
				destinationVersion:           "solelyVersion",
				destinationCluster:           "Kubernetes",
				requestProtocol:              "tcp",
				responseFlags:                "",
				connectionSecurityPolicy:     "mutual_tls",
				reporter:                     "source",
			},
			wantLogInfo: logInfo{
				direction:            "OUTBOUND",
				sourceAddress:        "10.19.25.33:49875",
				sourceWorkload:       "sleep",
				sourceNamespace:      "default",
				destinationAddress:   "10.19.25.34:80",
				destinationService:   "10.19.25.34",
				destinationWorkload:  "solelyWorkload",
				destinationNamespace: "default",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, loginfo := m.buildServiceMetric(tt.args.data)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantLogInfo, loginfo)
		})
	}
}

func TestBuildConnectionMetric(t *testing.T) {
	serviceCache := cache.NewServiceCache()
	serviceCache.AddOrUpdateService(&workloadapi.Service{
		Hostname:  "kmesh.kmesh-system.svc.cluster.local",
		Namespace: "kmesh-system",
		Name:      "kmesh",
		Addresses: []*workloadapi.NetworkAddress{
			{
				Address: net.ParseIP("192.168.1.22").To4(),
			},
		},
	})
	serviceCache.AddOrUpdateService(&workloadapi.Service{
		Hostname:  "httpbin.default.svc.cluster.local",
		Namespace: "default",
		Name:      "httpbin",
		Addresses: []*workloadapi.NetworkAddress{
			{
				Address: net.ParseIP("192.168.1.23").To4(),
			},
		},
	})

	workloadCache := cache.NewWorkloadCache()

	workloadCache.AddOrUpdateWorkload(&workloadapi.Workload{
		Namespace:         "default",
		Name:              "sleep",
		WorkloadName:      "sleep",
		CanonicalName:     "sleepCanonical",
		CanonicalRevision: "sleepVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Addresses: [][]byte{
			{10, 19, 25, 33},
		},
	})

	// kmesh workload with service attached
	workloadCache.AddOrUpdateWorkload(&workloadapi.Workload{
		Namespace:         "kmesh-system",
		Name:              "kmesh",
		WorkloadName:      "kmesh-daemon",
		CanonicalName:     "dstCanonical",
		CanonicalRevision: "dstVersion",
		ClusterId:         "Kubernetes",
		TrustDomain:       "cluster.local",
		ServiceAccount:    "default",
		Services: map[string]*workloadapi.PortList{
			"kmesh-system/kmesh.kmesh-system.svc.cluster.local": {
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8000,
					},
				},
			},
		},
		Addresses: [][]byte{
			{10, 19, 25, 31},
		},
	})
	type args struct {
		data *requestMetric
	}

	tests := []struct {
		name    string
		args    args
		want    connectionMetricLabels
		wantErr bool
	}{
		{
			name: "normal capability test",
			args: args{
				data: &requestMetric{
					conSrcDstInfo: connectionSrcDst{
						// sleep
						src: [4]uint32{nets.ConvertIpToUint32("10.19.25.33"), 0, 0, 0},
						// kmesh-daemon
						dst:     [4]uint32{nets.ConvertIpToUint32("10.19.25.31"), 0, 0, 0},
						dstPort: uint16(8000),
						srcPort: uint16(8000),
					},
					// kmesh-daemon
					origDstAddr:   [4]uint32{nets.ConvertIpToUint32("192.168.1.22"), 0, 0, 0},
					origDstPort:   uint16(8000),
					direction:     uint32(2),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: connectionMetricLabels{
				reporter:                "source",
				startTime:               "",
				sourceWorkload:          "sleep",
				sourceCanonicalService:  "sleepCanonical",
				sourceCanonicalRevision: "sleepVersion",
				sourceWorkloadNamespace: "default",
				sourcePrincipal:         "spiffe://cluster.local/ns/default/sa/default",
				sourceApp:               "sleepCanonical",
				sourceVersion:           "sleepVersion",
				sourceCluster:           "Kubernetes",
				sourceAddress:           "10.19.25.33:8000",

				destinationAddress:           "10.19.25.31:8000",
				destinationPodAddress:        "10.19.25.31",
				destinationPodNamespace:      "kmesh-system",
				destinationPodName:           "kmesh",
				destinationService:           "kmesh.kmesh-system.svc.cluster.local",
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

				requestProtocol: "tcp",
				responseFlags:   "",

				connectionSecurityPolicy: "mutual_tls",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				workloadCache: workloadCache,
				serviceCache:  serviceCache,
			}
			got := m.buildConnectionMetric(tt.args.data)
			got.startTime = ""
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Metric.buildMetric() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMetricController_updatePrometheusMetric(t *testing.T) {
	testworkloadLabel1 := workloadMetricLabels{
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
	}
	testworkloadLabel2 := workloadMetricLabels{
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
		destinationPodName:           "sleep",
		destinationWorkload:          "sleep",
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
	}

	testServiceLabel1 := serviceMetricLabels{
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
	}
	testServiceLabel2 := serviceMetricLabels{
		sourceWorkload:               "kmesh-daemon",
		sourceCanonicalService:       "srcCanonical",
		sourceCanonicalRevision:      "srcVersion",
		sourceWorkloadNamespace:      "kmesh-system",
		sourcePrincipal:              "spiffe://cluster.local/ns/kmesh-system/sa/default",
		sourceApp:                    "srcCanonical",
		sourceVersion:                "srcVersion",
		sourceCluster:                "Kubernetes",
		destinationService:           "sleep.kmesh-system.svc.cluster.local",
		destinationServiceNamespace:  "kmesh-system",
		destinationServiceName:       "sleep.kmesh-system.svc.cluster.local",
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
	}

	testConnLabel1 := connectionMetricLabels{
		reporter:                "source",
		startTime:               "0001-01-01 00:00:00 +0000 UTC",
		sourceWorkload:          "sleep",
		sourceCanonicalService:  "sleepCanonical",
		sourceCanonicalRevision: "sleepVersion",
		sourceWorkloadNamespace: "default",
		sourcePrincipal:         "spiffe://cluster.local/ns/default/sa/default",
		sourceApp:               "sleepCanonical",
		sourceVersion:           "sleepVersion",
		sourceCluster:           "Kubernetes",
		sourceAddress:           "10.19.25.33:8000",

		destinationAddress:           "10.19.25.31:8000",
		destinationPodAddress:        "10.19.25.31",
		destinationPodNamespace:      "kmesh-system",
		destinationPodName:           "kmesh",
		destinationService:           "kmesh.kmesh-system.svc.cluster.local",
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

		requestProtocol: "tcp",
		responseFlags:   "",

		connectionSecurityPolicy: "mutual_tls",
	}

	testConnLabel2 := connectionMetricLabels{
		reporter:                "destination",
		startTime:               "0001-01-01 00:00:00 +0000 UTC",
		sourceWorkload:          "sleep",
		sourceCanonicalService:  "sleepCanonical",
		sourceCanonicalRevision: "sleepVersion",
		sourceWorkloadNamespace: "default",
		sourcePrincipal:         "spiffe://cluster.local/ns/default/sa/default",
		sourceApp:               "sleepCanonical",
		sourceVersion:           "sleepVersion",
		sourceCluster:           "Kubernetes",
		sourceAddress:           "10.19.25.33:8000",

		destinationAddress:           "10.19.25.31:8000",
		destinationPodAddress:        "10.19.25.31",
		destinationPodNamespace:      "kmesh-system",
		destinationPodName:           "kmesh",
		destinationService:           "kmesh.kmesh-system.svc.cluster.local",
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

		requestProtocol: "tcp",
		responseFlags:   "",

		connectionSecurityPolicy: "mutual_tls",
	}

	workloadPrometheusLabel1 := struct2map(testworkloadLabel1)
	workloadPrometheusLabel2 := struct2map(testworkloadLabel2)
	servicePrometheusLabel1 := struct2map(testServiceLabel1)
	servicePrometheusLabel2 := struct2map(testServiceLabel2)
	connectionPrometheusLabel1 := struct2map(testConnLabel1)
	connectionPrometheusLabel2 := struct2map(testConnLabel2)

	tests := []struct {
		name                    string
		workloadMetricCache     workloadMetricInfo
		serviceMetricCache      serviceMetricInfo
		connectionMetricCache   connectionMetricInfo
		exportWorkloadMetrics   []*prometheus.GaugeVec
		exportServiceMetrics    []*prometheus.GaugeVec
		exportConnectionMetrics []*prometheus.GaugeVec
		want                    []float64
	}{
		{
			name: "update metric in Prometheus",
			workloadMetricCache: workloadMetricInfo{
				WorkloadConnOpened:        1,
				WorkloadConnClosed:        2,
				WorkloadConnFailed:        3,
				WorkloadConnSentBytes:     4,
				WorkloadConnReceivedBytes: 5,
				WorkloadConnPacketLost:    6,
				WorkloadConnTotalRetrans:  7,
			},
			serviceMetricCache: serviceMetricInfo{
				ServiceConnOpened:        6,
				ServiceConnClosed:        7,
				ServiceConnFailed:        8,
				ServiceConnSentBytes:     9,
				ServiceConnReceivedBytes: 10,
			},
			connectionMetricCache: connectionMetricInfo{
				ConnSentBytes:     1,
				ConnReceivedBytes: 2,
				ConnPacketLost:    3,
				ConnTotalRetrans:  4,
			},
			exportWorkloadMetrics: []*prometheus.GaugeVec{
				tcpConnectionOpenedInWorkload,
				tcpConnectionClosedInWorkload,
				tcpConnectionFailedInWorkload,
				tcpSentBytesInWorkload,
				tcpReceivedBytesInWorkload,
			},
			exportServiceMetrics: []*prometheus.GaugeVec{
				tcpConnectionOpenedInService,
				tcpConnectionClosedInService,
				tcpConnectionFailedInService,
				tcpSentBytesInService,
				tcpReceivedBytesInService,
			},
			exportConnectionMetrics: []*prometheus.GaugeVec{
				tcpConnectionTotalSendBytes,
				tcpConnectionTotalReceivedBytes,
				tcpConnectionTotalPacketLost,
				tcpConnectionTotalRetrans,
			},
			want: []float64{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			go RunPrometheusClient(ctx)
			m := &MetricController{
				workloadCache: cache.NewWorkloadCache(),
				workloadMetricCache: map[workloadMetricLabels]*workloadMetricInfo{
					testworkloadLabel1: &tt.workloadMetricCache,
					testworkloadLabel2: &tt.workloadMetricCache,
				},
				serviceMetricCache: map[serviceMetricLabels]*serviceMetricInfo{
					testServiceLabel1: &tt.serviceMetricCache,
					testServiceLabel2: &tt.serviceMetricCache,
				},
				connectionMetricCache: map[connectionMetricLabels]*connectionMetricInfo{
					testConnLabel1: &tt.connectionMetricCache,
					testConnLabel2: &tt.connectionMetricCache,
				},
			}
			m.updatePrometheusMetric()
			index := 0
			for _, metric := range tt.exportWorkloadMetrics {
				v1 := testutil.ToFloat64(metric.With(workloadPrometheusLabel1))
				assert.Equal(t, tt.want[index], v1)
				v2 := testutil.ToFloat64(metric.With(workloadPrometheusLabel2))
				assert.Equal(t, tt.want[index], v2)
				index = index + 1
			}
			for _, metric := range tt.exportServiceMetrics {
				v1 := testutil.ToFloat64(metric.With(servicePrometheusLabel1))
				assert.Equal(t, tt.want[index], v1)
				v2 := testutil.ToFloat64(metric.With(servicePrometheusLabel2))
				assert.Equal(t, tt.want[index], v2)
				index = index + 1
			}
			index = 0
			for _, metric := range tt.exportConnectionMetrics {
				v1 := testutil.ToFloat64(metric.With(connectionPrometheusLabel1))
				assert.Equal(t, tt.want[index], v1)
				v2 := testutil.ToFloat64(metric.With(connectionPrometheusLabel2))
				assert.Equal(t, tt.want[index], v2)
				index = index + 1
			}
			cancel()
		})
	}
}

func TestBuildV4Metric(t *testing.T) {
	buff := bytes.NewBuffer([]byte{10, 244, 1, 13, 10, 244, 1, 12, 34, 208, 144, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 10, 96, 46, 224, 144, 31, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 3, 0, 0, 0, 147, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 167, 122, 203, 84, 2, 0, 0, 0, 153, 163,
		210, 202, 232, 184, 0, 0, 64, 30, 158, 31, 235, 184, 0, 0, 0, 0, 0, 0, 150, 158, 0, 0, 19, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	data := requestMetric{

		conSrcDstInfo: connectionSrcDst{
			src:       [4]uint32{218231818, 0, 0, 0},
			dst:       [4]uint32{201454602, 0, 0, 0},
			direction: constants.OUTBOUND,
			srcPort:   53282,
			dstPort:   8080,
		},
		origDstAddr:    [4]uint32{3761135626, 0, 0, 0},
		origDstPort:    8080,
		direction:      constants.OUTBOUND,
		receivedBytes:  147,
		sentBytes:      3,
		state:          1,
		success:        1,
		duration:       10012555943,
		startTime:      203309974725529,
		lastReportTime: 203319987281472,
		srtt:           40598,
		minRtt:         19,
		totalRetrans:   0,
		packetLost:     0,
	}

	tests := []struct {
		name          string
		tcpConns      map[connectionSrcDst]connMetric
		newConnMetric connMetric
	}{
		{
			name:     "v4 metric test, tcpConn is empty",
			tcpConns: map[connectionSrcDst]connMetric{},
			newConnMetric: connMetric{
				receivedBytes: 147,
				sentBytes:     3,
				packetLost:    0,
				totalRetrans:  0,
				totalReports:  1,
			},
		},
		{
			name: "v4 metric test, tcpConns in not empty",
			tcpConns: map[connectionSrcDst]connMetric{
				data.conSrcDstInfo: {
					receivedBytes: 1,
					sentBytes:     1,
					packetLost:    0,
					totalRetrans:  0,
					totalReports:  1,
				},
			},
			newConnMetric: connMetric{
				receivedBytes: 147,
				sentBytes:     3,
				packetLost:    0,
				totalRetrans:  0,
				totalReports:  2,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			copiedBytes := make([]byte, len(buff.Bytes()))
			copy(copiedBytes, buff.Bytes())

			copiedBuff := bytes.NewBuffer(copiedBytes)
			prevTcpConns := make(map[connectionSrcDst]connMetric)
			for k, v := range tt.tcpConns {
				prevTcpConns[k] = v
			}

			got, err := buildV4Metric(copiedBuff, tt.tcpConns)
			if err != nil {
				t.Errorf("buildV4Metric() error = %v", err)
			}
			assert.Equal(t, tt.newConnMetric, tt.tcpConns[data.conSrcDstInfo])

			temp := data
			temp.sentBytes = temp.sentBytes - prevTcpConns[temp.conSrcDstInfo].sentBytes
			temp.receivedBytes = temp.receivedBytes - prevTcpConns[temp.conSrcDstInfo].receivedBytes
			temp.packetLost = temp.packetLost - prevTcpConns[temp.conSrcDstInfo].packetLost
			temp.totalRetrans = temp.totalRetrans - prevTcpConns[temp.conSrcDstInfo].totalRetrans
			assert.Equal(t, temp, got)
		})
	}
}
