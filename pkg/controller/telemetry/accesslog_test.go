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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_buildAccesslog(t *testing.T) {
	type args struct {
		conn_metrics connMetric
		req_metrics  requestMetric
		accesslog    logInfo
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "build accesslog",
			args: args{
				conn_metrics: connMetric{
					sentBytes:     uint32(60),
					receivedBytes: uint32(172),
				},
				req_metrics: requestMetric{
					duration:       uint64(2236000),
					startTime:      uint64(3506247005837715),
					lastReportTime: uint64(3506247005837715),
				},
				accesslog: logInfo{
					direction:            "INBOUND",
					sourceAddress:        "10.244.0.10:47667",
					sourceWorkload:       "sleep-7656cf8794-9v2gv",
					sourceNamespace:      "kmesh-system",
					destinationAddress:   "10.244.0.7:8080",
					destinationService:   "httpbin.ambient-demo.svc.cluster.local",
					destinationWorkload:  "httpbin-86b8ffc5ff-bhvxx",
					destinationNamespace: "kmesh-system",
					state:                "BPF_TCP_SYN_RECV",
				},
			},
			want: "2024-08-14 10:11:27.005837715 +0000 UTC src.addr=10.244.0.10:47667, src.workload=sleep-7656cf8794-9v2gv, src.namespace=kmesh-system, dst.addr=10.244.0.7:8080, dst.service=httpbin.ambient-demo.svc.cluster.local, dst.workload=httpbin-86b8ffc5ff-bhvxx, dst.namespace=kmesh-system, start_time=2024-08-14 10:11:27.005837715 +0000 UTC, direction=INBOUND, state=BPF_TCP_SYN_RECV, sent_bytes=60, received_bytes=172, packet_loss=0, retransmissions=0, srtt=0us, min_rtt=0us, duration=2.236ms",
		},
	}
	osStartTime = time.Date(2024, 7, 4, 20, 14, 0, 0, time.UTC)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildAccesslog(tt.args.req_metrics, tt.args.conn_metrics, tt.args.accesslog)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_getOSBootTime(t *testing.T) {
	t.Run("function test", func(t *testing.T) {
		_, err := getOSBootTime()
		assert.NoError(t, err)
	})
}

func Test_calculateUptime(t *testing.T) {
	startTime := time.Date(2024, 7, 4, 20, 42, 0, 0, time.UTC)
	elapsedTimeNs := uint64(3506247005837715)
	want := time.Date(2024, 8, 14, 10, 39, 27, 5837715, time.UTC)
	uptime := calculateUptime(startTime, elapsedTimeNs)
	assert.Equal(t, want, uptime)
}
