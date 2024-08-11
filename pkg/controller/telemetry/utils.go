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
	"net/http"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("pkg/telemetry")
	mu  sync.Mutex

	workloadLabels = []string{
		"reporter",
		"source_workload",
		"source_canonical_service",
		"source_canonical_revision",
		"source_workload_namespace",
		"source_principal",
		"source_app",
		"source_version",
		"source_cluster",
		"destination_pod_address",
		"destination_pod_namespace",
		"destination_pod_name",
		"destination_workload",
		"destination_canonical_service",
		"destination_canonical_revision",
		"destination_workload_namespace",
		"destination_principal",
		"destination_app",
		"destination_version",
		"destination_cluster",
		"request_protocol",
		"response_flags",
		"connection_security_policy",
	}

	serviceLabels = []string{
		"reporter",
		"source_workload",
		"source_canonical_service",
		"source_canonical_revision",
		"source_workload_namespace",
		"source_principal",
		"source_app",
		"source_version",
		"source_cluster",
		"destination_service",
		"destination_service_namespace",
		"destination_service_name",
		"destination_workload",
		"destination_canonical_service",
		"destination_canonical_revision",
		"destination_workload_namespace",
		"destination_principal",
		"destination_app",
		"destination_version",
		"destination_cluster",
		"request_protocol",
		"response_flags",
		"connection_security_policy",
	}

	labelsMap = map[string]string{
		"reporter":                     "reporter",
		"sourceWorkload":               "source_workload",
		"sourceCanonicalService":       "source_canonical_service",
		"sourceCanonicalRevision":      "source_canonical_revision",
		"sourceWorkloadNamespace":      "source_workload_namespace",
		"sourcePrincipal":              "source_principal",
		"sourceApp":                    "source_app",
		"sourceVersion":                "source_version",
		"sourceCluster":                "source_cluster",
		"destinationService":           "destination_service",
		"destinationServiceNamespace":  "destination_service_namespace",
		"destinationServiceName":       "destination_service_name",
		"destinationPodAddress":        "destination_pod_address",
		"destinationPodNamespace":      "destination_pod_namespace",
		"destinationPodName":           "destination_pod_name",
		"destinationWorkload":          "destination_workload",
		"destinationCanonicalService":  "destination_canonical_service",
		"destinationCanonicalRevision": "destination_canonical_revision",
		"destinationWorkloadNamespace": "destination_workload_namespace",
		"destinationPrincipal":         "destination_principal",
		"destinationApp":               "destination_app",
		"destinationVersion":           "destination_version",
		"destinationCluster":           "destination_cluster",
		"requestProtocol":              "request_protocol",
		"responseFlags":                "response_flags",
		"connectionSecurityPolicy":     "connection_security_policy",
	}
)

var (
	tcpConnectionOpenedInWorkload = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kmesh_tcp_connections_opened_total",
		Help: "The total number of TCP connections opened to a workload",
	}, workloadLabels)

	tcpConnectionClosedInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_connections_closed_total",
			Help: "The total number of TCP connections closed to a workload",
		}, workloadLabels)

	tcpReceivedBytesInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_received_bytes_total",
			Help: "The size of the total number of bytes received in response to a workload over a TCP connection.",
		}, workloadLabels)

	tcpSentBytesInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_sent_bytes_total",
			Help: "The size of the total number of bytes sent in response to a workload over a TCP connection.",
		}, workloadLabels)

	tcpConnectionFailedInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_conntections_failed_total",
			Help: "The total number of TCP connections failed to a workload.",
		}, workloadLabels)

	tcpConnectionOpenedInService = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kmesh_tcp_service_connections_opened_total",
		Help: "The total number of TCP connections opened to a service",
	}, serviceLabels)

	tcpConnectionClosedInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_service_connections_closed_total",
			Help: "The total number of TCP connections closed to a service",
		}, serviceLabels)

	tcpReceivedBytesInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_service_received_bytes_total",
			Help: "The size of the total number of bytes reveiced in response to a service over a TCP connection.",
		}, serviceLabels)

	tcpSentBytesInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_service_sent_bytes_total",
			Help: "The size of the total number of bytes sent in response to a service over a TCP connection.",
		}, serviceLabels)

	tcpConnectionFailedInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_service_conntections_failed_total",
			Help: "The total number of TCP connections failed to a service.",
		}, serviceLabels)
)

func RunPrometheusClient(ctx context.Context) {
	registry := prometheus.NewRegistry()
	for {
		select {
		case <-ctx.Done():
			return
		default:
			runPrometheusClient(registry)
		}
	}
}

func runPrometheusClient(registry *prometheus.Registry) {
	// ensure not occur matche the same requests as /status/metric panic
	mu.Lock()
	defer mu.Unlock()
	registry.MustRegister(tcpConnectionOpenedInWorkload, tcpConnectionClosedInWorkload, tcpReceivedBytesInWorkload, tcpSentBytesInWorkload)
	registry.MustRegister(tcpConnectionOpenedInService, tcpConnectionClosedInService, tcpReceivedBytesInService, tcpSentBytesInService)

	http.Handle("/status/metric", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		Registry: registry,
	}))
	if err := http.ListenAndServe(":15020", nil); err != nil {
		log.Fatalf("start prometheus client port failed: %v", err)
	}
}

func DeleteWorkloadMetric(workload *workloadapi.Workload) {
	if workload == nil {
		return
	}

	_ = tcpConnectionClosedInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpConnectionFailedInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpConnectionOpenedInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpReceivedBytesInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpSentBytesInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
}

func DeleteServiceMetric(serviceName string) {
	if serviceName == "" {
		return
	}
	svcHost := ""
	svcNamespace := ""
	if len(strings.Split(serviceName, "/")) != 2 {
		log.Info("get destination service host failed")
		return
	} else {
		svcNamespace = strings.Split(serviceName, "/")[0]
		svcHost = strings.Split(serviceName, "/")[1]
	}

	_ = tcpConnectionClosedInService.DeletePartialMatch(prometheus.Labels{"destination_service_name": svcHost, "destination_service_namespace": svcNamespace})
	_ = tcpConnectionFailedInService.DeletePartialMatch(prometheus.Labels{"destination_service_name": svcHost, "destination_service_namespace": svcNamespace})
	_ = tcpConnectionOpenedInService.DeletePartialMatch(prometheus.Labels{"destination_service_name": svcHost, "destination_service_namespace": svcNamespace})
	_ = tcpReceivedBytesInService.DeletePartialMatch(prometheus.Labels{"destination_service_name": svcHost, "destination_service_namespace": svcNamespace})
	_ = tcpSentBytesInService.DeletePartialMatch(prometheus.Labels{"destination_service_name": svcHost, "destination_service_namespace": svcNamespace})
}
