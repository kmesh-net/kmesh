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
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
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
				labels: adsMetricLabels{
					reporter:              "destination",
					sourcePodAddress:      "-",
					destinationPodAddress: "192.168.10.24",
				},
			},
			want: map[string]string{
				"reporter":                "destination",
				"source_pod_address":      "-",
				"source_pod_port":         "-",
				"destination_pod_address": "192.168.10.24",
				"destination_pod_port":    "-",
			},
		},
		{
			name: "empty commonTrafficLabels to map test",
			args: args{
				labels: adsMetricLabels{},
			},
			want: map[string]string{
				"reporter":                "-",
				"source_pod_address":      "-",
				"source_pod_port":         "-",
				"destination_pod_address": "-",
				"destination_pod_port":    "-",
			},
		},
		{
			name: "Only some fields in the commonTrafficLabels have values",
			args: args{
				labels: adsMetricLabels{
					reporter:              "source",
					sourcePodAddress:      "192.168.10.24",
					destinationPodAddress: "192.168.10.23",
				},
			},
			want: map[string]string{
				"reporter":                "source",
				"source_pod_address":      "192.168.10.24",
				"source_pod_port":         "-",
				"destination_pod_address": "192.168.10.23",
				"destination_pod_port":    "-",
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

func TestBuildAdsMetric(t *testing.T) {
	type args struct {
		data *requestMetric
	}
	tests := []struct {
		name    string
		args    args
		want    adsMetricLabels
		wantErr bool
	}{
		{
			name: "normal capability test",
			args: args{
				data: &requestMetric{
					src:           [4]uint32{521736970, 0, 0, 0},
					dst:           [4]uint32{383822016, 0, 0, 0},
					srcPort:       uint16(36895),
					dstPort:       uint16(37151),
					sentBytes:     uint32(156),
					receivedBytes: uint32(1024),
				},
			},
			want: adsMetricLabels{
				sourcePodAddress:      "10.19.25.31",
				sourcePodPort:         "8080",
				destinationPodAddress: "192.168.224.22",
				destinationPodPort:    "8081",
				reporter:              "",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := MetricController{
				adsMetricCache: map[adsMetricLabels]*adsMetricInfo{},
			}

			got := m.buildAdsMetric(tt.args.data)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Metric.buildMetric() = %v, want %v", got, tt.want)
			}
		})
	}
}
