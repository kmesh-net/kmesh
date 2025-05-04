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
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

func TestRegisterMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				runPrometheusClient(registry)
			}
		}
	}()

	exportMetrics := []*prometheus.GaugeVec{
		tcpConnectionClosedInWorkload,
		tcpConnectionOpenedInWorkload,
		tcpReceivedBytesInWorkload,
		tcpSentBytesInWorkload,
		tcpConnectionFailedInWorkload,
		tcpConnectionClosedInService,
		tcpConnectionOpenedInService,
		tcpReceivedBytesInService,
		tcpSentBytesInService,
		tcpConnectionFailedInService,
		tcpConnectionTotalSendBytes,
		tcpConnectionTotalReceivedBytes,
		tcpConnectionTotalPacketLost,
		tcpConnectionTotalRetrans,
	}

	workloadLabels := map[string]string{
		"reporter":                       "destination",
		"source_workload":                "sleep",
		"source_canonical_service":       "sleep",
		"source_canonical_revision":      "latest",
		"source_workload_namespace":      "ambient-demo",
		"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
		"source_app":                     "sleep",
		"source_version":                 "latest",
		"source_cluster":                 "Kubernetes",
		"destination_pod_address":        "192.068.10.25",
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
	}

	serviceLabels := map[string]string{
		"reporter":                       "destination",
		"source_workload":                "sleep",
		"source_canonical_service":       "sleep",
		"source_canonical_revision":      "latest",
		"source_workload_namespace":      "ambient-demo",
		"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
		"source_app":                     "sleep",
		"source_version":                 "latest",
		"source_cluster":                 "Kubernetes",
		"destination_service":            "sleep.ambient.svc.cluster.local",
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
	}

	connectionLabels := map[string]string{
		"reporter":                       "destination",
		"start_time":                     "2023-10-01T00:00:00Z",
		"source_workload":                "sleep",
		"source_canonical_service":       "sleep",
		"source_canonical_revision":      "latest",
		"source_workload_namespace":      "ambient-demo",
		"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
		"source_app":                     "sleep",
		"source_version":                 "latest",
		"source_cluster":                 "Kubernetes",
		"source_address":                 "192.068.10.24:5665",
		"destination_address":            "192.068.10.25:80",
		"destination_pod_address":        "192.068.10.25",
		"destination_pod_namespace":      "ambient-demo",
		"destination_pod_name":           "httpbin-hjsrf",
		"destination_service":            "sleep.ambient.svc.cluster.local",
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
	}

	tcpConnectionClosedInWorkload.With(workloadLabels).Set(2)
	tcpConnectionOpenedInWorkload.With(workloadLabels).Set(4)
	tcpReceivedBytesInWorkload.With(workloadLabels).Set(12.64)
	tcpSentBytesInWorkload.With(workloadLabels).Set(11.45)
	tcpConnectionFailedInWorkload.With(workloadLabels).Set(1.0)

	tcpConnectionClosedInService.With(serviceLabels).Set(4)
	tcpReceivedBytesInService.With(serviceLabels).Set(8)
	tcpSentBytesInService.With(serviceLabels).Set(9)
	tcpConnectionOpenedInService.With(serviceLabels).Set(16.25)
	tcpConnectionFailedInService.With(serviceLabels).Set(6.0)

	tcpConnectionTotalSendBytes.With(connectionLabels).Set(12.64)
	tcpConnectionTotalReceivedBytes.With(connectionLabels).Set(11.45)
	tcpConnectionTotalPacketLost.With(connectionLabels).Set(1.0)
	tcpConnectionTotalRetrans.With(connectionLabels).Set(2.0)

	for _, metric := range exportMetrics {
		if err := prometheus.Register(metric); err != nil {
			t.Errorf("metric not register")
		}
	}
	cancel()
}

func TestDeleteWorkloadMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				runPrometheusClient(registry)
			}
		}
	}()

	exportMetrics := []*prometheus.GaugeVec{
		tcpConnectionClosedInWorkload,
		tcpConnectionOpenedInWorkload,
		tcpReceivedBytesInWorkload,
		tcpSentBytesInWorkload,
		tcpConnectionFailedInWorkload,
	}

	workloadLabels := map[string]string{
		"reporter":                       "destination",
		"source_workload":                "sleep",
		"source_canonical_service":       "sleep",
		"source_canonical_revision":      "latest",
		"source_workload_namespace":      "ambient-demo",
		"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
		"source_app":                     "sleep",
		"source_version":                 "latest",
		"source_cluster":                 "Kubernetes",
		"destination_pod_address":        "192.068.10.25",
		"destination_pod_namespace":      "ambient-demo",
		"destination_pod_name":           "httpbin-hjsrf",
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
	}
	type args struct {
		workload *workloadapi.Workload
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "delete workload",
			args: args{
				workload: &workloadapi.Workload{
					Name:      "httpbin-hjsrf",
					Namespace: "ambient-demo",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcpConnectionClosedInWorkload.With(workloadLabels).Set(2)
			tcpConnectionOpenedInWorkload.With(workloadLabels).Set(4)
			tcpReceivedBytesInWorkload.With(workloadLabels).Set(12.64)
			tcpSentBytesInWorkload.With(workloadLabels).Set(11.45)
			tcpConnectionFailedInWorkload.With(workloadLabels).Set(1.0)

			deleteWorkloadMetricInPrometheus(tt.args.workload)

			for _, metric := range exportMetrics {
				if err := prometheus.Register(metric); err == nil {
					t.Errorf("metric not clean up")
				}
			}
		})
	}
	cancel()
}

func TestDeleteServiceMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				runPrometheusClient(registry)
			}
		}
	}()

	exportMetrics := []*prometheus.GaugeVec{
		tcpConnectionClosedInService,
		tcpConnectionOpenedInService,
		tcpReceivedBytesInService,
		tcpSentBytesInService,
		tcpConnectionFailedInService,
	}
	serviceLabels := map[string]string{
		"reporter":                       "destination",
		"source_workload":                "sleep",
		"source_canonical_service":       "sleep",
		"source_canonical_revision":      "latest",
		"source_workload_namespace":      "ambient-demo",
		"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
		"source_app":                     "sleep",
		"source_version":                 "latest",
		"source_cluster":                 "Kubernetes",
		"destination_service":            "sleep.ambient.svc.cluster.local",
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
	}

	type args struct {
		serviceName string
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "delete service",
			args: args{
				serviceName: "ambient-demo/tcp-echo",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcpConnectionClosedInService.With(serviceLabels).Set(4)
			tcpReceivedBytesInService.With(serviceLabels).Set(8)
			tcpSentBytesInService.With(serviceLabels).Set(9)
			tcpConnectionOpenedInService.With(serviceLabels).Set(16.25)
			tcpConnectionFailedInService.With(serviceLabels).Set(6.0)

			deleteServiceMetricInPrometheus(tt.args.serviceName)
			for _, metric := range exportMetrics {
				if err := prometheus.Register(metric); err == nil {
					t.Errorf("metric not clean up")
				}
			}
		})
	}
	cancel()
}

func TestDeleteConnectionMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				runPrometheusClient(registry)
			}
		}
	}()

	exportMetrics := []*prometheus.GaugeVec{
		tcpConnectionTotalSendBytes,
		tcpConnectionTotalReceivedBytes,
		tcpConnectionTotalPacketLost,
		tcpConnectionTotalRetrans,
	}

	connectionLabels := map[string]string{
		"reporter":                       "destination",
		"start_time":                     "2023-10-01T00:00:00Z",
		"source_workload":                "sleep",
		"source_canonical_service":       "sleep",
		"source_canonical_revision":      "latest",
		"source_workload_namespace":      "ambient-demo",
		"source_principal":               "spiffe://cluster.local/ns/ambient-demo/sa/sleep",
		"source_app":                     "sleep",
		"source_version":                 "latest",
		"source_cluster":                 "Kubernetes",
		"source_address":                 "192.068.10.24:5665",
		"destination_address":            "192.068.10.25:80",
		"destination_pod_address":        "192.068.10.25",
		"destination_pod_namespace":      "ambient-demo",
		"destination_pod_name":           "httpbin-hjsrf",
		"destination_service":            "sleep.ambient.svc.cluster.local",
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
	}
	type args struct {
		connLabels *connectionMetricLabels
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "delete connection",
			args: args{
				connLabels: &connectionMetricLabels{
					sourceAddress:      "192.068.10.24:5665",
					destinationAddress: "192.068.10.25:80",
					responseFlags:      "-",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tcpConnectionTotalSendBytes.With(connectionLabels).Set(12.64)
			tcpConnectionTotalReceivedBytes.With(connectionLabels).Set(11.45)
			tcpConnectionTotalPacketLost.With(connectionLabels).Set(1.0)
			tcpConnectionTotalRetrans.With(connectionLabels).Set(2.0)

			deleteConnectionMetricInPrometheus(tt.args.connLabels)

			for _, metric := range exportMetrics {
				if err := prometheus.Register(metric); err == nil {
					t.Errorf("metric not clean up")
				}
			}
		})
	}
	cancel()
}
