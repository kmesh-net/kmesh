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

package adstelemetry

import (
	"context"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"kmesh.net/kmesh/pkg/controller/ads/cache"
	"kmesh.net/kmesh/pkg/logger"
)

var (
	log = logger.NewLoggerScope("adstelemetry")
	// ensure not occur matche the same requests as /status/metric panic in unit test
	mu sync.Mutex
	// Ensure concurrency security when removing metriclabels from workloads and services.
	deleteLock    sync.Mutex
	deleteAds     = []*cache.Adsconfig{}
	deleteService = []string{}

	adsLabels = []string{
		"reporter",
		"source_pod_address",
		"source_pod_port",
		"source_pod_name",
		"destination_pod_address",
		"destination_pod_port",
		"destination_svc_name",
	}

	labelsMap = map[string]string{
		"reporter":              "reporter",
		"sourcePodAddress":      "source_pod_address",
		"sourcePodPort":         "source_pod_port",
		"sourcePodName":         "source_pod_name",
		"destinationPodAddress": "destination_pod_address",
		"destinationPodPort":    "destination_pod_port",
		"destinationSvcName":    "destination_svc_name",
	}
)

var (
	tcpConnectionOpenedInAds = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "kmesh_tcp_ads_connections_opened_total",
		Help: "The total number of TCP connections opened to a ads",
	}, adsLabels)

	tcpConnectionClosedInAds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_ads_connections_closed_total",
			Help: "The total number of TCP connections closed to a ads",
		}, adsLabels)

	tcpReceivedBytesInAds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_ads_received_bytes_total",
			Help: "The size of the total number of bytes received in response to a ads over a TCP connection.",
		}, adsLabels)

	tcpSentBytesInAds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_ads_sent_bytes_total",
			Help: "The size of the total number of bytes sent in response to a ads over a TCP connection.",
		}, adsLabels)

	tcpConnectionFailedInAds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_ads_conntections_failed_total",
			Help: "The total number of TCP connections failed to a ads.",
		}, adsLabels)

	tcpConnectionTotalRetransInAds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "kmesh_tcp_retrans_total",
			Help: "Total number of retransmissions of the ads over the TCP connection.",
		}, adsLabels)
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
	// ensure not occur matche the same requests as /status/metric panic in unit test
	mu.Lock()
	defer mu.Unlock()
	registry.MustRegister(tcpConnectionOpenedInAds, tcpConnectionClosedInAds, tcpReceivedBytesInAds, tcpSentBytesInAds, tcpConnectionTotalRetransInAds)

	http.Handle("/status/metric", promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		Registry: registry,
	}))
	if err := http.ListenAndServe(":15020", nil); err != nil {
		log.Fatalf("start prometheus client port failed: %v", err)
	}
}

func DeleteAdsMetric(adsconfig *cache.Adsconfig) {
	if adsconfig == nil {
		return
	}
	deleteLock.Lock()
	deleteAds = append(deleteAds, adsconfig)
	deleteLock.Unlock()
}

func deleteAdsMetricInPrometheus(ads *cache.Adsconfig) {
	// delete destination ads metric labels
	_ = tcpConnectionClosedInAds.DeletePartialMatch(prometheus.Labels{"destination_address": ads.Address, "destination_pod_namespace": ads.Namespace})
	_ = tcpConnectionFailedInAds.DeletePartialMatch(prometheus.Labels{"destination_address": ads.Address, "destination_addressspace": ads.Namespace})
	_ = tcpConnectionOpenedInAds.DeletePartialMatch(prometheus.Labels{"destination_address": ads.Address, "destination_addressspace": ads.Namespace})
	_ = tcpReceivedBytesInAds.DeletePartialMatch(prometheus.Labels{"destination_address": ads.Address, "destination_addressspace": ads.Namespace})
	_ = tcpSentBytesInAds.DeletePartialMatch(prometheus.Labels{"destination_address": ads.Address, "destination_addressspace": ads.Namespace})
	_ = tcpConnectionTotalRetransInAds.DeletePartialMatch(prometheus.Labels{"destination_address": ads.Address, "destination_addressspace": ads.Namespace})
	// delete source ads metric labels
	_ = tcpConnectionClosedInAds.DeletePartialMatch(prometheus.Labels{"source_workload": ads.Name, "source_workload_namespace": ads.Namespace})
	_ = tcpConnectionFailedInAds.DeletePartialMatch(prometheus.Labels{"source_workload": ads.Name, "source_workload_namespace": ads.Namespace})
	_ = tcpConnectionOpenedInAds.DeletePartialMatch(prometheus.Labels{"source_workload": ads.Name, "source_workload_namespace": ads.Namespace})
	_ = tcpReceivedBytesInAds.DeletePartialMatch(prometheus.Labels{"source_workload": ads.Name, "source_workload_namespace": ads.Namespace})
	_ = tcpSentBytesInAds.DeletePartialMatch(prometheus.Labels{"source_workload": ads.Name, "source_workload_namespace": ads.Namespace})
	_ = tcpConnectionTotalRetransInAds.DeletePartialMatch(prometheus.Labels{"source_workload": ads.Name, "source_workload_namespace": ads.Namespace})
}
