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
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerField("pkg/auth")

	trafficLabels = []string{
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

type metricKey struct {
	srcIp uint32
	dstIp uint32
}

type metricValue struct {
	direction        uint8
	connectionOpen   uint32
	connectionClose  uint32
	connectionFailed uint32
	sentBytes        uint32
	receivedBytes    uint32
}

type requestMetric struct {
	src []byte
	dst []byte
	// source or destination
	reporter         []byte
	connectionOpened uint32
	connectionClosed uint32
	receivedBytes    uint32
	sentBytes        uint32
	success          bool
}

type commonTrafficLabels struct {
	reporter string

	sourceWorkload          string
	sourceCanonicalService  string
	sourceCanonicalRevision string
	sourceWorkloadNamespace string
	sourcePrincipal         string
	sourceApp               string
	sourceVersion           string
	sourceCluster           string

	destinationService           string
	destinationServiceNamespace  string
	destinationServiceName       string
	destinationWorkload          string
	destinationCanonicalService  string
	destinationCanonicalRevision string
	destinationWorkloadNamespace string
	destinationPrincipal         string
	destinationApp               string
	destinationVersion           string
	destinationCluster           string

	requestProtocol          string
	responseFlags            string
	connectionSecurityPolicy string
}

var (
	tcpConnectionOpened = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kmesh_tcp_connections_opened_total",
		Help: "The total number of TCP connections opened",
	}, trafficLabels)

	tcpConnectionClosed = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_connections_closed_total",
			Help: "The total number of TCP connections closed",
		}, trafficLabels)

	tcpReceivedBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_received_bytes_total",
			Help: "The size of total bytes received during request in case of a TCP connection",
		}, trafficLabels)

	tcpSentBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_sent_bytes_total",
			Help: "The size of total bytes sent during response in case of a TCP connection",
		}, trafficLabels)
)

func RunPrometheusClient() {
	registry := prometheus.NewRegistry()
	runPrometheusClient(registry)
}

func runPrometheusClient(registry *prometheus.Registry) {
	registry.MustRegister(tcpConnectionOpened, tcpConnectionClosed, tcpReceivedBytes, tcpSentBytes)

	http.Handle("/status/metric", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		Registry: registry,
	}))
	if err := http.ListenAndServe(":15020", nil); err != nil {
		log.Fatalf("start prometheus client port failed: %v", err)
	}
}
