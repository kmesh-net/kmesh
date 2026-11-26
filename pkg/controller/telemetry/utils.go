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
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/util/wait"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	metricsServerAddr    = ":15020"
	metricsPath          = "/status/metric"
	metricsServerTimeout = 20 * time.Second
)

var (
	log = logger.NewLoggerScope("telemetry")
	// metricsServerRetryPeriod is how long RunPrometheusClient waits before
	// starting the metrics server again after it fails.
	metricsServerRetryPeriod = 5 * time.Second
	// Ensure concurrency security when removing metriclabels from workloads and services.
	deleteLock       sync.Mutex
	deleteWorkload   = []*workloadapi.Workload{}
	deleteService    = []string{}
	deleteConnection = []*connectionMetricLabels{}

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

	connectionLabels = []string{
		"reporter",
		"start_time",
		"source_workload",
		"source_canonical_service",
		"source_canonical_revision",
		"source_workload_namespace",
		"source_principal",
		"source_app",
		"source_version",
		"source_cluster",
		"source_address",
		"destination_address",
		"destination_pod_address",
		"destination_pod_namespace",
		"destination_pod_name",
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
		"startTime":                    "start_time",
		"sourceWorkload":               "source_workload",
		"sourceCanonicalService":       "source_canonical_service",
		"sourceCanonicalRevision":      "source_canonical_revision",
		"sourceWorkloadNamespace":      "source_workload_namespace",
		"sourcePrincipal":              "source_principal",
		"sourceApp":                    "source_app",
		"sourceVersion":                "source_version",
		"sourceCluster":                "source_cluster",
		"sourceAddress":                "source_address",
		"destinationAddress":           "destination_address",
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
		"nodeName":                     "node_name",
		"mapId":                        "map_id",
		"mapName":                      "map_name",
		"mapType":                      "map_type",
		"operationType":                "operation_type",
		"pidTgid":                      "pid_tgid",
	}
	operationLabels = []string{
		"node_name",
		"operation_type",
	}

	kmeshMapLabels = []string{
		"node_name",
		"map_name",
	}
	totalMapLabels = []string{
		"node_name",
	}
)

var (
	tcpConnectionOpenedInWorkload = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kmesh_tcp_workload_connections_opened_total",
		Help: "The total number of TCP connections opened to a workload",
	}, workloadLabels)

	tcpConnectionClosedInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_workload_connections_closed_total",
			Help: "The total number of TCP connections closed to a workload",
		}, workloadLabels)

	tcpReceivedBytesInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_workload_received_bytes_total",
			Help: "The size of the total number of bytes received in response to a workload over a TCP connection.",
		}, workloadLabels)

	tcpSentBytesInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_workload_sent_bytes_total",
			Help: "The size of the total number of bytes sent in response to a workload over a TCP connection.",
		}, workloadLabels)

	tcpConnectionFailedInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_workload_conntections_failed_total",
			Help: "The total number of TCP connections failed to a workload.",
		}, workloadLabels)

	tcpConnectionTotalRetransInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_retrans_total",
			Help: "Total number of retransmissions of the workload over the TCP connection.",
		}, workloadLabels)

	tcpConnectionPacketLostInWorkload = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_packet_loss_total",
			Help: "Tracks the total number of TCP packets lost between source and destination.",
		}, workloadLabels)

	tcpConnectionOpenedInService = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kmesh_tcp_connections_opened_total",
		Help: "The total number of TCP connections opened to a service",
	}, serviceLabels)

	tcpConnectionClosedInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_connections_closed_total",
			Help: "The total number of TCP connections closed to a service",
		}, serviceLabels)

	tcpReceivedBytesInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_received_bytes_total",
			Help: "The size of the total number of bytes reveiced in response to a service over a TCP connection.",
		}, serviceLabels)

	tcpSentBytesInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_sent_bytes_total",
			Help: "The size of the total number of bytes sent in response to a service over a TCP connection.",
		}, serviceLabels)

	tcpConnectionFailedInService = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_conntections_failed_total",
			Help: "The total number of TCP connections failed to a service.",
		}, serviceLabels)

	// Metrics to track the status of long lived TCP connections
	tcpConnectionTotalSendBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_connection_sent_bytes_total",
			Help: "The total number of bytes sent over established TCP connection.",
		}, connectionLabels)

	tcpConnectionTotalReceivedBytes = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_connection_received_bytes_total",
			Help: "The total number of bytes received over established TCP connection.",
		}, connectionLabels)

	tcpConnectionTotalPacketLost = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_connection_packet_lost_total",
			Help: "Total number of packets lost during transmission in a TCP connection.",
		}, connectionLabels)

	tcpConnectionTotalRetrans = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_connection_retrans_total",
			Help: "The total number of retransmits over established TCP connection.",
		}, connectionLabels)

	// New operation metrics
	bpfProgOpDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "kmesh_bpf_prog_operation_duration",
			Help: "Duration of bpf prog operation in ns.",
		},
		operationLabels,
	)

	bpfProgOpCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kmesh_bpf_prog_operation_count",
			Help: "Count of bpf prog operations executed.",
		},
		operationLabels,
	)
	mapEntryCount = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_map_entry_count",
			Help: "The total entry used by an eBPF map.",
		}, kmeshMapLabels,
	)
	mapCountInNode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_map_count_total",
			Help: "Count of map created by kmesh-daemon.",
		}, totalMapLabels,
	)
)

// RunPrometheusClient serves the metrics on :15020 until ctx is done.
// If the server cannot listen or stops with an error, the error is logged
// and the server is started again after metricsServerRetryPeriod, so a
// port conflict does not stop the daemon.
func RunPrometheusClient(ctx context.Context) {
	handler := newMetricsHandler(newMetricsRegistry())
	runMetricsServer(ctx, metricsServerAddr, handler, metricsServerRetryPeriod)
}

// newMetricsRegistry returns a registry with every exported metric registered once.
func newMetricsRegistry() *prometheus.Registry {
	registry := prometheus.NewRegistry()
	registry.MustRegister(tcpConnectionOpenedInWorkload, tcpConnectionClosedInWorkload, tcpReceivedBytesInWorkload, tcpSentBytesInWorkload, tcpConnectionTotalRetransInWorkload, tcpConnectionPacketLostInWorkload)
	registry.MustRegister(tcpConnectionOpenedInService, tcpConnectionClosedInService, tcpReceivedBytesInService, tcpSentBytesInService)
	registry.MustRegister(tcpConnectionTotalSendBytes, tcpConnectionTotalReceivedBytes, tcpConnectionTotalPacketLost, tcpConnectionTotalRetrans)
	registry.MustRegister(bpfProgOpDuration, bpfProgOpCount)
	registry.MustRegister(mapEntryCount, mapCountInNode)
	return registry
}

// newMetricsHandler serves the registry on its own mux, so only metricsPath
// is exposed and nothing registered on http.DefaultServeMux leaks onto the port.
func newMetricsHandler(registry *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()
	mux.Handle(metricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		Registry: registry,
	}))
	return mux
}

func runMetricsServer(ctx context.Context, addr string, handler http.Handler, retryPeriod time.Duration) {
	wait.UntilWithContext(ctx, func(ctx context.Context) {
		if err := serveMetrics(ctx, addr, handler); err != nil {
			log.Errorf("prometheus metrics server on %s failed, retrying in %v: %v", addr, retryPeriod, err)
		}
	}, retryPeriod)
}

// serveMetrics serves handler on addr until ctx is done or the server fails.
// It returns nil after a shutdown caused by ctx.
func serveMetrics(ctx context.Context, addr string, handler http.Handler) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:      handler,
		ReadTimeout:  metricsServerTimeout,
		WriteTimeout: metricsServerTimeout,
	}
	serveDone := make(chan struct{})
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), metricsServerTimeout)
			defer cancel()
			if err := server.Shutdown(shutdownCtx); err != nil {
				log.Errorf("failed to shut down prometheus metrics server on %s: %v", addr, err)
			}
		case <-serveDone:
		}
	}()

	err = server.Serve(ln)
	close(serveDone)
	<-shutdownDone
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func DeleteWorkloadMetric(workload *workloadapi.Workload) {
	if workload == nil {
		return
	}
	deleteLock.Lock()
	deleteWorkload = append(deleteWorkload, workload)
	deleteLock.Unlock()
}

func deleteWorkloadMetricInPrometheus(workload *workloadapi.Workload) {
	// delete destination workload metric labels
	_ = tcpConnectionClosedInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpConnectionFailedInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpConnectionOpenedInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpReceivedBytesInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpSentBytesInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpConnectionTotalRetransInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	_ = tcpConnectionPacketLostInWorkload.DeletePartialMatch(prometheus.Labels{"destination_pod_name": workload.Name, "destination_pod_namespace": workload.Namespace})
	// delete source workload metric labels
	_ = tcpConnectionClosedInWorkload.DeletePartialMatch(prometheus.Labels{"source_workload": workload.Name, "source_workload_namespace": workload.Namespace})
	_ = tcpConnectionFailedInWorkload.DeletePartialMatch(prometheus.Labels{"source_workload": workload.Name, "source_workload_namespace": workload.Namespace})
	_ = tcpConnectionOpenedInWorkload.DeletePartialMatch(prometheus.Labels{"source_workload": workload.Name, "source_workload_namespace": workload.Namespace})
	_ = tcpReceivedBytesInWorkload.DeletePartialMatch(prometheus.Labels{"source_workload": workload.Name, "source_workload_namespace": workload.Namespace})
	_ = tcpSentBytesInWorkload.DeletePartialMatch(prometheus.Labels{"source_workload": workload.Name, "source_workload_namespace": workload.Namespace})
	_ = tcpConnectionTotalRetransInWorkload.DeletePartialMatch(prometheus.Labels{"source_workload": workload.Name, "source_workload_namespace": workload.Namespace})
	_ = tcpConnectionPacketLostInWorkload.DeletePartialMatch(prometheus.Labels{"source_workload": workload.Name, "source_workload_namespace": workload.Namespace})
}

func DeleteServiceMetric(serviceName string) {
	if serviceName == "" {
		return
	}
	deleteLock.Lock()
	deleteService = append(deleteService, serviceName)
	deleteLock.Unlock()
}

func deleteServiceMetricInPrometheus(serviceName string) {
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

func deleteConnectionMetricInPrometheus(connLabels *connectionMetricLabels) {
	_ = tcpConnectionTotalSendBytes.DeletePartialMatch(prometheus.Labels{"source_address": connLabels.sourceAddress, "destination_address": connLabels.destinationAddress})
	_ = tcpConnectionTotalReceivedBytes.DeletePartialMatch(prometheus.Labels{"source_address": connLabels.sourceAddress, "destination_address": connLabels.destinationAddress})
	_ = tcpConnectionTotalPacketLost.DeletePartialMatch(prometheus.Labels{"source_address": connLabels.sourceAddress, "destination_address": connLabels.destinationAddress})
	_ = tcpConnectionTotalRetrans.DeletePartialMatch(prometheus.Labels{"source_address": connLabels.sourceAddress, "destination_address": connLabels.destinationAddress})
}
