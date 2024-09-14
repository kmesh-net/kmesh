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

package status

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sort"
	"strconv"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"istio.io/istio/pilot/test/util"

	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/workload"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils/test"
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

		assert.Equal(t, http.StatusOK, w.Code)

		var loggerInfo LoggerInfo
		err := json.Unmarshal(w.Body.Bytes(), &loggerInfo)
		assert.Nil(t, err)

		expectedLoggerLevel, err := logger.GetLoggerLevel(loggerName)
		assert.Nil(t, err)

		assert.Equal(t, loggerInfo.Level, expectedLoggerLevel.String())
		assert.Equal(t, loggerInfo.Name, loggerName)
	}

	req := httptest.NewRequest(http.MethodGet, patternLoggers, nil)
	w := httptest.NewRecorder()
	server.getLoggerLevel(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	expectedLoggerNames := append(logger.GetLoggerNames(), bpfLoggerName)
	var actualLoggerNames []string
	err := json.Unmarshal(w.Body.Bytes(), &actualLoggerNames)
	assert.Nil(t, err)

	sort.Strings(expectedLoggerNames)
	sort.Strings(actualLoggerNames)
	assert.Equal(t, expectedLoggerNames, actualLoggerNames)
}

func TestServer_getAndSetBpfLevel(t *testing.T) {
	// Test in two modes
	configs := []options.BpfConfig{{
		Mode:        "ads",
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}, {
		Mode:        "workload",
		BpfFsPath:   "/sys/fs/bpf",
		Cgroup2Path: "/mnt/kmesh_cgroup2",
	}}

	testLoggerLevelMap := map[string]int{
		"error": constants.BPF_LOG_ERR,
		"warn":  constants.BPF_LOG_WARN,
		"info":  constants.BPF_LOG_INFO,
		"debug": constants.BPF_LOG_DEBUG,
	}
	key := uint32(0)
	actualLoggerLevel := uint32(0)
	for _, config := range configs {
		t.Run(config.Mode, func(t *testing.T) {
			cleanup, bpfLoader := test.InitBpfMap(t, config)
			defer cleanup()
			server := &Server{
				xdsClient: &controller.XdsClient{
					WorkloadController: &workload.Controller{
						Processor: nil,
					},
				},
				bpfLogLevelMap: bpfLoader.GetBpfLogLevel(),
			}

			setLoggerUrl := patternLoggers
			for logLevelStr, logLevelInt := range testLoggerLevelMap {
				// We support both string and number
				testLoggerLevels := []string{logLevelStr, strconv.FormatInt(int64(logLevelInt), 10)}
				expectedLoggerLevel := uint32(logLevelInt)
				for _, testLoggerLevel := range testLoggerLevels {
					loggerInfo := LoggerInfo{
						Name:  bpfLoggerName,
						Level: testLoggerLevel,
					}
					reqBody, _ := json.Marshal(loggerInfo)
					req := httptest.NewRequest(http.MethodPost, setLoggerUrl, bytes.NewReader(reqBody))
					w := httptest.NewRecorder()
					server.setLoggerLevel(w, req)

					assert.Equal(t, http.StatusOK, w.Code)
					server.bpfLogLevelMap.Lookup(&key, &actualLoggerLevel)
					assert.Equal(t, expectedLoggerLevel, actualLoggerLevel)
				}
			}

			// test get bpf log level
			getLoggerUrl := patternLoggers + "?name=" + bpfLoggerName
			req := httptest.NewRequest(http.MethodGet, getLoggerUrl, nil)
			w := httptest.NewRecorder()
			server.getLoggerLevel(w, req)

			var (
				actualLoggerInfo   LoggerInfo
				expectedLoggerInfo *LoggerInfo
			)
			err := json.Unmarshal(w.Body.Bytes(), &actualLoggerInfo)
			assert.Nil(t, err)

			expectedLoggerInfo, err = server.getBpfLogLevel()
			assert.Nil(t, err)
			assert.NotNil(t, expectedLoggerInfo)
			assert.Equal(t, expectedLoggerInfo.Level, actualLoggerInfo.Level)
			assert.Equal(t, expectedLoggerInfo.Name, actualLoggerInfo.Name)
		})
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

			assert.Equal(t, http.StatusOK, w.Code)
			actualLoggerLevel, err := logger.GetLoggerLevel(loggerName)
			assert.Nil(t, err)
			assert.Equal(t, loggerInfo.Level, actualLoggerLevel.String())
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
	fakeWorkloadCache.AddOrUpdateWorkload(w1)
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

func TestServer_dumpWorkloadBpfMap(t *testing.T) {
	t.Run("Ads mode test", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        "ads",
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, _ := test.InitBpfMap(t, config)
		defer cleanup()

		// ads mode will failed
		server := &Server{}
		req := httptest.NewRequest(http.MethodPost, patternBpfWorkloadMaps, nil)
		w := httptest.NewRecorder()
		server.configDumpWorkload(w, req)

		body, err := io.ReadAll(w.Body)
		assert.Nil(t, err)
		assert.Equal(t, invalidModeErrMessage, string(body))
	})

	t.Run("Workload mode test", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        "workload",
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, bpfLoader := test.InitBpfMap(t, config)
		bpfMaps := bpfLoader.GetBpfKmeshWorkload().SockConn.KmeshCgroupSockWorkloadMaps
		defer cleanup()

		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					Processor: workload.NewProcessor(bpfMaps),
				},
			},
		}

		// do some updates
		testWorkloadPolicyKeys := []bpfcache.WorkloadPolicy_key{
			{WorklodId: 1}, {WorklodId: 2},
		}
		testWorkloadPolicyVals := []bpfcache.WorkloadPolicy_value{
			{PolicyIds: [4]uint32{1, 2, 3, 4}}, {PolicyIds: [4]uint32{5, 6, 7, 8}},
		}
		_, err := bpfMaps.MapOfWlPolicy.BatchUpdate(testWorkloadPolicyKeys, testWorkloadPolicyVals, nil)
		assert.Nil(t, err)

		testBackendKeys := []bpfcache.BackendKey{
			{BackendUid: 1}, {BackendUid: 2},
		}
		testBackendVals := []bpfcache.BackendValue{
			{WaypointPort: 1234}, {WaypointPort: 5678},
		}

		_, err = bpfMaps.KmeshBackend.BatchUpdate(testBackendKeys, testBackendVals, nil)
		assert.Nil(t, err)

		testEndpointKeys := []bpfcache.EndpointKey{
			{ServiceId: 1}, {ServiceId: 2},
		}
		testEndpointVals := []bpfcache.EndpointValue{
			{BackendUid: 1234}, {BackendUid: 5678},
		}

		_, err = bpfMaps.KmeshEndpoint.BatchUpdate(testEndpointKeys, testEndpointVals, nil)
		assert.Nil(t, err)

		testFrontendKeys := []bpfcache.FrontendKey{
			{Ip: [16]byte{1, 2, 3, 4}}, {Ip: [16]byte{5, 6, 7, 8}},
		}
		testFrontendVals := []bpfcache.FrontendValue{
			{UpstreamId: 1234}, {UpstreamId: 5678},
		}
		_, err = bpfMaps.KmeshFrontend.BatchUpdate(testFrontendKeys, testFrontendVals, nil)
		assert.Nil(t, err)

		testServiceKeys := []bpfcache.ServiceKey{
			{ServiceId: 1}, {ServiceId: 2},
		}
		testServiceVals := []bpfcache.ServiceValue{
			{EndpointCount: 1234}, {EndpointCount: 5678},
		}
		_, err = bpfMaps.KmeshService.BatchUpdate(testServiceKeys, testServiceVals, nil)
		assert.Nil(t, err)

		req := httptest.NewRequest(http.MethodPost, patternBpfWorkloadMaps, nil)
		w := httptest.NewRecorder()
		server.bpfWorkloadMaps(w, req)
		body, err := io.ReadAll(w.Body)
		assert.Nil(t, err)
		dump := WorkloadBpfDump{}
		json.Unmarshal(body, &dump)

		assert.Equal(t, len(testWorkloadPolicyVals), len(dump.WorkloadPolicies))
		assert.Equal(t, len(testBackendVals), len(dump.Backends))
		assert.Equal(t, len(testEndpointVals), len(dump.Endpoints))
		assert.Equal(t, len(testFrontendVals), len(dump.Frontends))
		assert.Equal(t, len(testServiceVals), len(dump.Services))

		fmt.Printf("Dump: %v\n", dump)
	})
}
