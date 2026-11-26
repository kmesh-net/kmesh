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
	"io"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"kmesh.net/kmesh/api/v2/workloadapi"
)

func TestRegisterMetrics(t *testing.T) {
	newMetricsRegistry()

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
}

func TestDeleteWorkloadMetric(t *testing.T) {
	newMetricsRegistry()

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
}

func TestDeleteServiceMetric(t *testing.T) {
	newMetricsRegistry()

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
}

func TestDeleteConnectionMetric(t *testing.T) {
	newMetricsRegistry()

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
}

func TestRunMetricsServerPortConflict(t *testing.T) {
	// Hold the port so every attempt to start the metrics server fails.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	addr := ln.Addr().String()

	assert.Error(t, serveMetrics(context.Background(), addr, newMetricsHandler(newMetricsRegistry())))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMetricsServer(ctx, addr, newMetricsHandler(newMetricsRegistry()), 10*time.Millisecond)
	}()

	// Let it fail and retry a few times; the test process must keep running.
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runMetricsServer did not return after the context was cancelled")
	}
}

var registerDefaultMuxHandler sync.Once

func TestServeMetrics(t *testing.T) {
	// A handler on http.DefaultServeMux must not be served by the metrics server.
	registerDefaultMuxHandler.Do(func() {
		http.HandleFunc("/debug/telemetry-default-mux", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	})
	mapCountInNode.WithLabelValues("telemetry-test-node").Set(1)
	defer mapCountInNode.DeleteLabelValues("telemetry-test-node")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- serveMetrics(ctx, addr, newMetricsHandler(newMetricsRegistry()))
	}()

	get := func(path string) (int, string, error) {
		resp, err := http.Get("http://" + addr + path)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body), err
	}
	require.Eventually(t, func() bool {
		_, _, err := get(metricsPath)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{path: metricsPath, wantStatus: http.StatusOK, wantBody: "kmesh_map_count_total"},
		{path: "/debug/telemetry-default-mux", wantStatus: http.StatusNotFound},
		{path: "/debug/pprof/", wantStatus: http.StatusNotFound},
	}
	for _, tt := range tests {
		status, body, err := get(tt.path)
		require.NoError(t, err)
		assert.Equal(t, tt.wantStatus, status, tt.path)
		assert.Contains(t, body, tt.wantBody, tt.path)
	}

	cancel()
	select {
	case err := <-errCh:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("serveMetrics did not return after the context was cancelled")
	}
	_, _, err = get(metricsPath)
	assert.Error(t, err, "the metrics server should be stopped")
}
