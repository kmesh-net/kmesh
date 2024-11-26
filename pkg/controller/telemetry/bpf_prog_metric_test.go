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
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestBuildOperationMetricLabel(t *testing.T) {
	os.Setenv("NODE_NAME", "test-node")
	defer os.Unsetenv("NODE_NAME")

	tests := []struct {
		name     string
		data     *operationTimeMetric
		expected operationMetricLabels
	}{
		{
			name: "valid operationTimeMetric",
			data: &operationTimeMetric{
				operationType: SOCK_TRAFFIC_CONTROL,
			},
			expected: operationMetricLabels{
				nodeName:      "test-node",
				operationType: "SOCK_TRAFFIC_CONTROL",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildOperationMetricLabel(tt.data)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestUpdateOperationMetricCache(t *testing.T) {
	tests := []struct {
		name          string
		data          operationDuration
		labels        operationMetricLabels
		expectedCache map[operationMetricLabels]operationDuration
	}{
		{
			name: "update cache with valid data",
			data: operationDuration{
				durations:     []uint64{100, 200},
				operationType: SOCK_TRAFFIC_CONTROL,
			},
			labels: operationMetricLabels{
				nodeName:      "test-node",
				operationType: "SOCK_TRAFFIC_CONTROL",
			},
			expectedCache: map[operationMetricLabels]operationDuration{
				{
					nodeName:      "test-node",
					operationType: "SOCK_TRAFFIC_CONTROL",
				}: {
					durations:     []uint64{100, 200},
					operationType: SOCK_TRAFFIC_CONTROL,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bpfMetric := NewBpfProgMetric()
			bpfMetric.updateOperationMetricCache(tt.data, tt.labels)
			assert.Equal(t, tt.expectedCache, bpfMetric.operationMetricCache)
		})
	}
}
func TestBpfProgMetric_updatePrometheusMetric(t *testing.T) {
	testOperationLabel1 := operationMetricLabels{
		nodeName:      "test-node-1",
		operationType: "SOCK_TRAFFIC_CONTROL",
	}
	testOperationLabel2 := operationMetricLabels{
		nodeName:      "test-node-2",
		operationType: "XDP_SHUTDOWN",
	}
	prometheusLabel1 := struct2map(testOperationLabel1)
	prometheusLabel2 := struct2map(testOperationLabel2)
	tests := []struct {
		name                 string
		operationMetricCache map[operationMetricLabels]operationDuration
		expectedMetricName   string
		wantDurations        map[string]float64
		wantCounts           map[string]float64
	}{
		{
			name: "update Prometheus metric with operation metrics",
			operationMetricCache: map[operationMetricLabels]operationDuration{
				testOperationLabel1: {
					durations:     []uint64{100, 200},
					operationType: SOCK_TRAFFIC_CONTROL,
				},
				testOperationLabel2: {
					durations:     []uint64{300, 400},
					operationType: XDP_SHUTDOWN,
				},
			},
			expectedMetricName: "bpf_prog_op_duration_seconds",
			wantDurations: map[string]float64{
				labelsToString(prometheusLabel1): 300,
				labelsToString(prometheusLabel2): 700,
			},
			wantCounts: map[string]float64{
				labelsToString(prometheusLabel1): 2,
				labelsToString(prometheusLabel2): 2,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bpfMetric := NewBpfProgMetric()
			bpfMetric.operationMetricCache = tt.operationMetricCache
			bpfMetric.updatePrometheusMetric()
			metrics, err := prometheus.DefaultGatherer.Gather()
			assert.NoError(t, err)
			for _, mf := range metrics {
				if mf.GetName() == tt.expectedMetricName {
					for _, m := range mf.GetMetric() {
						labels := make(map[string]string)
						for _, lp := range m.GetLabel() {
							labels[lp.GetName()] = lp.GetValue()
						}
						labelKey := labelsToString(labels)
						if expectedSum, ok := tt.wantDurations[labelKey]; ok {
							assert.Equal(t, expectedSum, m.GetHistogram().GetSampleSum(), "Duration sum mismatch for labels: %v", labels)
						}
						if expectedCount, ok := tt.wantCounts[labelKey]; ok {
							assert.Equal(t, expectedCount, m.GetHistogram().GetSampleCount(), "Count mismatch for labels: %v", labels)
						}
					}
				}
			}
		})
	}
}

func labelsToString(labels map[string]string) string {
	result := ""
	for k, v := range labels {
		result += k + "=" + v + ","
	}
	return result
}
