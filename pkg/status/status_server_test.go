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

package status

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/sirupsen/logrus"
	"istio.io/istio/pilot/test/util"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/logger"
)

func TestServer_getLoggerLevel(t *testing.T) {
	server := &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{
				Processor: nil,
			},
		},
	}
	loggerNames := logger.GetLoggerNames()
	for _, loggerName := range loggerNames {
		getLoggerUrl := patternLoggers + "?name=" + loggerName
		req := httptest.NewRequest(http.MethodGet, getLoggerUrl, nil)
		w := httptest.NewRecorder()
		server.getLoggerLevel(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status code %d, but got %d", http.StatusOK, w.Code)
		}

		var loggerInfo LoggerInfo
		err := json.Unmarshal(w.Body.Bytes(), &loggerInfo)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		expectedLoggerLevel, err := logger.GetLoggerLevel(loggerName)
		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}

		if expectedLoggerLevel.String() != loggerInfo.Level {
			t.Errorf("Wrong logger level, expected %s, but got %s", expectedLoggerLevel.String(), loggerInfo.Level)
		}

		if loggerName != loggerInfo.Name {
			t.Errorf("Wrong logger name, expected %s, but got %s", loggerName, loggerInfo.Name)
		}
	}
}

func TestServer_setLoggerLevel(t *testing.T) {
	server := &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{
				Processor: nil,
			},
		},
	}
	loggerNames := logger.GetLoggerNames()
	testLoggerLevels := []string{
		logrus.PanicLevel.String(),
		logrus.FatalLevel.String(),
		logrus.ErrorLevel.String(),
		logrus.WarnLevel.String(),
		logrus.InfoLevel.String(),
		logrus.DebugLevel.String(),
		logrus.TraceLevel.String(),
	}
	for _, loggerName := range loggerNames {
		setLoggerUrl := patternLoggers
		for _, testLoggerLevel := range testLoggerLevels {
			loggerInfo := LoggerInfo{
				Name:  loggerName,
				Level: testLoggerLevel,
			}
			reqBody, _ := json.Marshal(loggerInfo)
			req := httptest.NewRequest(http.MethodPost, setLoggerUrl, bytes.NewReader(reqBody))
			w := httptest.NewRecorder()
			server.setLoggerLevel(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status code %d, but got %d", http.StatusOK, w.Code)
			}

			actualLoggerLevel, err := logger.GetLoggerLevel(loggerName)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if actualLoggerLevel.String() != loggerInfo.Level {
				t.Errorf("Wrong logger level, expected %s, but got %s", loggerInfo.Level, actualLoggerLevel.String())
			}
		}
	}
}

func TestServer_configDumpWorkload(t *testing.T) {
	w1 := &workloadapi.Workload{
		Uid:               "cluster0//Pod/ns/name",
		Namespace:         "ns",
		Name:              "name",
		Addresses:         [][]byte{netip.AddrFrom4([4]byte{1, 2, 3, 4}).AsSlice()},
		Network:           "testnetwork",
		CanonicalName:     "foo",
		CanonicalRevision: "latest",
		WorkloadType:      workloadapi.WorkloadType_POD,
		WorkloadName:      "name",
		Status:            workloadapi.WorkloadStatus_HEALTHY,
		ClusterId:         "cluster0",
		Services: map[string]*workloadapi.PortList{
			"ns/hostname": {
				Ports: []*workloadapi.Port{
					{
						ServicePort: 80,
						TargetPort:  8080,
					},
					{
						ServicePort: 81,
						TargetPort:  8180,
					},
					{
						ServicePort: 82,
						TargetPort:  82,
					},
				},
			},
		},
		Waypoint: &workloadapi.GatewayAddress{
			Destination: &workloadapi.GatewayAddress_Address{
				Address: &workloadapi.NetworkAddress{
					Network: "testnetwork",
					Address: []byte{192, 168, 1, 10},
				},
			},
		},
	}
	svc := &workloadapi.Service{
		Name:      "svc",
		Namespace: "ns",
		Hostname:  "hostname",
		Ports: []*workloadapi.Port{
			{
				ServicePort: 80,
				TargetPort:  8080,
			},
			{
				ServicePort: 81,
				TargetPort:  0,
			},
			{
				ServicePort: 82,
				TargetPort:  0,
			},
		},
		Waypoint: &workloadapi.GatewayAddress{
			Destination: &workloadapi.GatewayAddress_Address{
				Address: &workloadapi.NetworkAddress{
					Network: "testnetwork",
					Address: []byte{192, 168, 1, 11},
				},
			},
		}}
	fakeWorkloadCache := cache.NewWorkloadCache()
	fakeServiceCache := cache.NewServiceCache()
	fakeWorkloadCache.AddWorkload(w1)
	fakeServiceCache.AddOrUpdateService(svc)
	// Create a new instance of the Server struct
	server := &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{
				Processor: &workload.Processor{
					WorkloadCache: fakeWorkloadCache,
					ServiceCache:  fakeServiceCache,
				},
			},
		},
	}

	// Create a new HTTP request and response
	req := httptest.NewRequest(http.MethodGet, "/configDumpWorkload", nil)
	w := httptest.NewRecorder()

	// Call the configDumpWorkload function
	server.configDumpWorkload(w, req)

	// Check the response status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, w.Code)
	}

	util.RefreshGoldenFile(t, w.Body.Bytes(), "./testdata/workload_configdump.json")

	util.CompareContent(t, w.Body.Bytes(), "./testdata/workload_configdump.json")
}
