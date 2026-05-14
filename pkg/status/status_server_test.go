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
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/encoding/protojson"
	"istio.io/istio/pilot/test/util"

	"kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/api/v2/cluster"
	"kmesh.net/kmesh/api/v2/core"
	"kmesh.net/kmesh/api/v2/listener"
	"kmesh.net/kmesh/api/v2/workloadapi"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/auth"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/ads"
	"kmesh.net/kmesh/pkg/controller/telemetry"
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

func buildWorkload(name string) *workloadapi.Workload {
	return &workloadapi.Workload{
		Uid:               "cluster0//Pod/ns/name",
		Namespace:         "ns",
		Name:              name,
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
}

func buildService(name, hostname string) *workloadapi.Service {
	return &workloadapi.Service{
		Name:      name,
		Namespace: "ns",
		Hostname:  hostname,
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
}

func TestServer_configDumpWorkload(t *testing.T) {
	w := buildWorkload("name")
	svc := buildService("svc", "hostname")

	policy := &security.Authorization{
		Name:      "policy",
		Namespace: "ns",
		Scope:     security.Scope_GLOBAL,
		Action:    security.Action_ALLOW,
	}
	fakeWorkloadCache := cache.NewWorkloadCache()
	fakeServiceCache := cache.NewServiceCache()
	fakeWorkloadCache.AddOrUpdateWorkload(w)
	fakeServiceCache.AddOrUpdateService(svc)
	fakeAuth := auth.NewRbac(fakeWorkloadCache)
	fakeAuth.UpdatePolicy(policy)
	// Create a new instance of the Server struct
	server := &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{
				Processor: &workload.Processor{
					WorkloadCache: fakeWorkloadCache,
					ServiceCache:  fakeServiceCache,
				},
				Rbac: fakeAuth,
			},
		},
	}

	// Create a new HTTP request and response
	req1 := httptest.NewRequest(http.MethodGet, "/configDumpWorkload", nil)
	w1 := httptest.NewRecorder()

	// Call the configDumpWorkload function
	server.configDumpWorkload(w1, req1)

	// Check the response status code
	if w1.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, w1.Code)
	}

	util.RefreshGoldenFile(t, w1.Body.Bytes(), "./testdata/workload_configdump.json")

	util.CompareContent(t, w1.Body.Bytes(), "./testdata/workload_configdump.json")

	fakeWorkloadCache = cache.NewWorkloadCache()
	fakeServiceCache = cache.NewServiceCache()

	workloads := []*workloadapi.Workload{}
	services := []*workloadapi.Service{}

	for i := 0; i < 10; i++ {
		w := buildWorkload(fmt.Sprintf("workload-%d", i))
		w.Uid = fmt.Sprintf("cluster0//Pod/ns/workload-%d", i)
		workloads = append(workloads, w)
		svc := buildService(fmt.Sprintf("service-%d", i), fmt.Sprintf("hostname-%d", i))
		services = append(services, svc)

		fakeWorkloadCache.AddOrUpdateWorkload(w)
		fakeServiceCache.AddOrUpdateService(svc)
	}

	// Create a new HTTP response
	w2 := httptest.NewRecorder()

	server = &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{
				Processor: &workload.Processor{
					WorkloadCache: fakeWorkloadCache,
					ServiceCache:  fakeServiceCache,
				},
				Rbac: fakeAuth,
			},
		},
	}

	// Call the configDumpWorkload function
	server.configDumpWorkload(w2, req1)

	// Check the response status code
	if w2.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, w2.Code)
	}

	util.RefreshGoldenFile(t, w2.Body.Bytes(), "./testdata/workload_configdump_original_sorted.json")
	util.CompareContent(t, w2.Body.Bytes(), "./testdata/workload_configdump_original_sorted.json")

	fakeWorkloadCache = cache.NewWorkloadCache()
	fakeServiceCache = cache.NewServiceCache()
	// Modify workloads and services properties
	for i := 0; i < 5; i++ { // Modify first 5 items
		// Modify workload properties
		w := buildWorkload(fmt.Sprintf("workload-%d-modified", i))
		w.ClusterId = "cluster1" // Changed cluster
		w.Uid = fmt.Sprintf("cluster1//Pod/ns/workload-%d-modified", i)
		w.Status = workloadapi.WorkloadStatus_UNHEALTHY

		workloads[i] = w
		// Modify service properties
		svc := buildService(fmt.Sprintf("service-%d-modified", i), fmt.Sprintf("hostname-%d-modified", i))
		// Modify service ports
		svc.Ports = []*workloadapi.Port{
			{
				ServicePort: 90,
				TargetPort:  9090,
			},
			{
				ServicePort: 91,
				TargetPort:  0,
			},
			{
				ServicePort: 92,
				TargetPort:  0,
			},
		}
		services[i] = svc
	}
	for _, w := range workloads {
		fakeWorkloadCache.AddOrUpdateWorkload(w)
	}
	for _, svc := range services {
		fakeServiceCache.AddOrUpdateService(svc)
	}

	w3 := httptest.NewRecorder()

	server = &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{
				Processor: &workload.Processor{
					WorkloadCache: fakeWorkloadCache,
					ServiceCache:  fakeServiceCache,
				},
				Rbac: fakeAuth,
			},
		},
	}

	server.configDumpWorkload(w3, req1)

	if w3.Code != http.StatusOK {
		t.Errorf("Expected status code %d, but got %d", http.StatusOK, w3.Code)
	}

	util.RefreshGoldenFile(t, w3.Body.Bytes(), "./testdata/workload_configdump_modified_sorted.json")
	util.CompareContent(t, w3.Body.Bytes(), "./testdata/workload_configdump_modified_sorted.json")
}

func TestServer_dumpWorkloadBpfMap(t *testing.T) {
	t.Run("Ads mode test", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        constants.KernelNativeMode,
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

	t.Run("Dual engine mode test", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        constants.DualEngineMode,
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, bpfLoader := test.InitBpfMap(t, config)
		bpfMaps := bpfLoader.GetBpfWorkload().SockConn.KmeshCgroupSockWorkloadMaps
		defer cleanup()

		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					Processor: workload.NewProcessor(bpfMaps),
				},
			},
		}

		// do some updates
		testWorkloadPolicyKeys := []bpfcache.WorkloadPolicyKey{
			{WorklodId: 1}, {WorklodId: 2},
		}
		testWorkloadPolicyVals := []bpfcache.WorkloadPolicyValue{
			{PolicyIds: [4]uint32{1, 2, 3, 4}}, {PolicyIds: [4]uint32{5, 6, 7, 8}},
		}
		_, err := bpfMaps.KmWlpolicy.BatchUpdate(testWorkloadPolicyKeys, testWorkloadPolicyVals, nil)
		assert.Nil(t, err)

		testBackendKeys := []bpfcache.BackendKey{
			{BackendUid: 1}, {BackendUid: 2},
		}
		testBackendVals := []bpfcache.BackendValue{
			{WaypointPort: 1234}, {WaypointPort: 5678},
		}

		_, err = bpfMaps.KmBackend.BatchUpdate(testBackendKeys, testBackendVals, nil)
		assert.Nil(t, err)

		testEndpointKeys := []bpfcache.EndpointKey{
			{ServiceId: 1}, {ServiceId: 2},
		}
		testEndpointVals := []bpfcache.EndpointValue{
			{BackendUid: 1234}, {BackendUid: 5678},
		}

		_, err = bpfMaps.KmEndpoint.BatchUpdate(testEndpointKeys, testEndpointVals, nil)
		assert.Nil(t, err)

		testFrontendKeys := []bpfcache.FrontendKey{
			{Ip: [16]byte{1, 2, 3, 4}}, {Ip: [16]byte{5, 6, 7, 8}},
		}
		testFrontendVals := []bpfcache.FrontendValue{
			{UpstreamId: 1234}, {UpstreamId: 5678},
		}
		_, err = bpfMaps.KmFrontend.BatchUpdate(testFrontendKeys, testFrontendVals, nil)
		assert.Nil(t, err)

		testServiceKeys := []bpfcache.ServiceKey{
			{ServiceId: 1}, {ServiceId: 2},
		}
		testServiceVals := []bpfcache.ServiceValue{
			{EndpointCount: [7]uint32{1234, 1234, 1234, 1234, 1234, 1234, 1234}}, {EndpointCount: [7]uint32{5678, 5678, 5678, 5678, 5678, 5678, 5678}},
		}
		_, err = bpfMaps.KmService.BatchUpdate(testServiceKeys, testServiceVals, nil)
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

func TestServer_dumpAdsBpfMap(t *testing.T) {
	t.Run("Dual engine mode test", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        constants.DualEngineMode,
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, _ := test.InitBpfMap(t, config)
		defer cleanup()

		// dual engine mode will fail
		server := &Server{}
		req := httptest.NewRequest(http.MethodGet, patternBpfWorkloadMaps, nil)
		w := httptest.NewRecorder()
		server.configDumpWorkload(w, req)

		body, err := io.ReadAll(w.Body)
		assert.Nil(t, err)
		assert.Equal(t, invalidModeErrMessage, string(body))
	})

	t.Run("Ads mode test", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        constants.KernelNativeMode,
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, _ := test.InitBpfMap(t, config)
		defer cleanup()

		server := &Server{
			xdsClient: &controller.XdsClient{
				AdsController: &ads.Controller{},
			},
		}

		testClusterKeys := []string{"t1", "t2"}
		testClusters := []*cluster.Cluster{
			{Name: testClusterKeys[0]},
			{Name: testClusterKeys[1]},
		}

		for index, testClusterKey := range testClusterKeys {
			testCluster := testClusters[index]
			maps_v2.ClusterUpdate(testClusterKey, testCluster)
		}

		testListenerKeys := []*core.SocketAddress{
			{Port: 1}, {Port: 2},
		}
		testListeners := []*listener.Listener{{Name: "t1"}, {Name: "t2"}}

		for index, testListenerKey := range testListenerKeys {
			testListener := testListeners[index]
			maps_v2.ListenerUpdate(testListenerKey, testListener)
		}

		req := httptest.NewRequest(http.MethodGet, patternBpfAdsMaps, nil)
		w := httptest.NewRecorder()
		server.bpfAdsMaps(w, req)
		body, err := io.ReadAll(w.Body)
		fmt.Printf("dump: %s\n", string(body))
		assert.Nil(t, err)

		dump := admin.ConfigDump{}
		err = protojson.Unmarshal(body, &dump)
		assert.Nil(t, err)

		assert.Equal(t, len(testClusters), len(dump.DynamicResources.ClusterConfigs))
		assert.Equal(t, len(testListeners), len(dump.DynamicResources.ListenerConfigs))
	})
}

func TestServerMetricHandler(t *testing.T) {
	t.Run("change accesslog, workload metrics and connection metric config info", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        constants.DualEngineMode,
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, loader := test.InitBpfMap(t, config)
		defer cleanup()

		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: loader,
		}
		server.xdsClient.WorkloadController.MetricController.EnableWorkloadMetric.Store(true)
		server.xdsClient.WorkloadController.MetricController.EnableConnectionMetric.Store(true)
		server.xdsClient.WorkloadController.MetricController.EnableAccesslog.Store(false)

		url := fmt.Sprintf("%s?enable=%s", patternMonitoring, "true")
		req := httptest.NewRequest(http.MethodPost, url, nil)
		w := httptest.NewRecorder()
		server.monitoringHandler(w, req)

		url = fmt.Sprintf("%s?enable=%s", patternAccesslog, "false")
		req = httptest.NewRequest(http.MethodPost, url, nil)
		w = httptest.NewRecorder()
		server.accesslogHandler(w, req)

		assert.Equal(t, false, server.xdsClient.WorkloadController.GetAccesslogTrigger())

		url = fmt.Sprintf("%s?enable=%s", patternWorkloadMetrics, "false")
		req = httptest.NewRequest(http.MethodPost, url, nil)
		w = httptest.NewRecorder()
		server.workloadMetricHandler(w, req)

		assert.Equal(t, false, server.xdsClient.WorkloadController.GetWorklaodMetricTrigger())

		url = fmt.Sprintf("%s?enable=%s", patternConnectionMetrics, "false")
		req = httptest.NewRequest(http.MethodPost, url, nil)
		w = httptest.NewRecorder()
		server.connectionMetricHandler(w, req)

		assert.Equal(t, false, server.xdsClient.WorkloadController.GetConnectionMetricTrigger())
	})

	t.Run("when monitoring is disable, cannot enable accesslog, workload metrics and connection metrics", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        constants.DualEngineMode,
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, loader := test.InitBpfMap(t, config)
		defer cleanup()

		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: loader,
		}

		server.xdsClient.WorkloadController.MetricController.EnableAccesslog.Store(false)

		url := fmt.Sprintf("%s?enable=%s", patternMonitoring, "false")
		req := httptest.NewRequest(http.MethodPost, url, nil)
		w := httptest.NewRecorder()
		server.monitoringHandler(w, req)

		assert.Equal(t, false, server.xdsClient.WorkloadController.GetMonitoringTrigger())

		url = fmt.Sprintf("%s?enable=%s", patternAccesslog, "true")
		req = httptest.NewRequest(http.MethodPost, url, nil)
		w = httptest.NewRecorder()
		server.accesslogHandler(w, req)

		assert.Equal(t, false, server.xdsClient.WorkloadController.GetAccesslogTrigger())

		url = fmt.Sprintf("%s?enable=%s", patternWorkloadMetrics, "true")
		req = httptest.NewRequest(http.MethodPost, url, nil)
		w = httptest.NewRecorder()
		server.workloadMetricHandler(w, req)

		assert.Equal(t, false, server.xdsClient.WorkloadController.GetWorklaodMetricTrigger())

		url = fmt.Sprintf("%s?enable=%s", patternConnectionMetrics, "true")
		req = httptest.NewRequest(http.MethodPost, url, nil)
		w = httptest.NewRecorder()
		server.connectionMetricHandler(w, req)

		assert.Equal(t, false, server.xdsClient.WorkloadController.GetConnectionMetricTrigger())
	})
}

func TestServerMonitoringHandler(t *testing.T) {
	t.Run("change monitoring config info", func(t *testing.T) {
		config := options.BpfConfig{
			Mode:        constants.DualEngineMode,
			BpfFsPath:   "/sys/fs/bpf",
			Cgroup2Path: "/mnt/kmesh_cgroup2",
		}
		cleanup, l := test.InitBpfMap(t, config)
		defer cleanup()

		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: l,
		}
		server.xdsClient.WorkloadController.MetricController.EnableMonitoring.Store(false)
		server.xdsClient.WorkloadController.MetricController.EnableAccesslog.Store(false)

		url := fmt.Sprintf("%s?enable=%s", patternMonitoring, "true")
		req := httptest.NewRequest(http.MethodPost, url, nil)
		w := httptest.NewRecorder()
		server.monitoringHandler(w, req)

		assert.Equal(t, true, server.xdsClient.WorkloadController.GetMonitoringTrigger())
		assert.Equal(t, true, server.xdsClient.WorkloadController.GetAccesslogTrigger())
		enableMonitoring := l.GetEnableMonitoring()
		assert.Equal(t, constants.ENABLED, enableMonitoring)
	})
}

func TestServer_version(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternVersion, nil)
	w := httptest.NewRecorder()
	server.version(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Body.Bytes())
}

func TestServer_readyProbe(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternReadyProbe, nil)
	w := httptest.NewRecorder()
	server.readyProbe(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "OK", w.Body.String())
}

func TestServer_loggersHandler(t *testing.T) {
	server := &Server{}

	req := httptest.NewRequest(http.MethodGet, patternLoggers, nil)
	w := httptest.NewRecorder()
	server.loggersHandler(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	req = httptest.NewRequest(http.MethodPost, patternLoggers, bytes.NewReader([]byte("invalid-json")))
	w = httptest.NewRecorder()
	server.loggersHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	req = httptest.NewRequest(http.MethodDelete, patternLoggers, nil)
	w = httptest.NewRecorder()
	server.loggersHandler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServer_checkWorkloadMode(t *testing.T) {
	server := &Server{xdsClient: nil}
	w := httptest.NewRecorder()
	result := server.checkWorkloadMode(w)
	assert.False(t, result)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_checkAdsMode(t *testing.T) {
	server := &Server{xdsClient: nil}
	w := httptest.NewRecorder()
	result := server.checkAdsMode(w)
	assert.False(t, result)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_checkBpfLoader(t *testing.T) {
	server := &Server{loader: nil}
	w := httptest.NewRecorder()
	result := server.checkBpfLoader(w)
	assert.False(t, result)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}


func TestServer_accesslogHandler_InvalidMethod(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternAccesslog, nil)
	w := httptest.NewRecorder()
	server.accesslogHandler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestServer_accesslogHandler_InvalidParam(t *testing.T) {
	server := &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{},
		},
		loader: nil, 
	}
	url := fmt.Sprintf("%s?enable=%s", patternAccesslog, "notabool")
	req := httptest.NewRequest(http.MethodPost, url, nil)
	w := httptest.NewRecorder()

	server.accesslogHandler(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}


func TestServer_monitoringHandler_InvalidMethod(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternMonitoring, nil)
	w := httptest.NewRecorder()
	server.monitoringHandler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}


func TestServer_workloadMetricHandler_InvalidMethod(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternWorkloadMetrics, nil)
	w := httptest.NewRecorder()
	server.workloadMetricHandler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}


func TestServer_connectionMetricHandler_InvalidMethod(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternConnectionMetrics, nil)
	w := httptest.NewRecorder()
	server.connectionMetricHandler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}


func TestServer_authzHandler_InvalidMethod(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternAuthz, nil)
	w := httptest.NewRecorder()
	server.authzHandler(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}


func TestServer_authzHandler_NilClient(t *testing.T) {
	server := &Server{xdsClient: nil}
	req := httptest.NewRequest(http.MethodPost, patternAuthz+"?enable=true", nil)
	w := httptest.NewRecorder()
	server.authzHandler(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}


func TestServer_authzHandler_InvalidParam(t *testing.T) {
	server := &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: &workload.Controller{},
		},
		loader: nil,
	}
	req := httptest.NewRequest(http.MethodPost, patternAuthz+"?enable=notabool", nil)
	w := httptest.NewRecorder()
	server.authzHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}


func TestServer_getBpfLogLevel_NilLoader(t *testing.T) {
	server := &Server{loader: nil}
	info, err := server.getBpfLogLevel()
	assert.Nil(t, info)
	assert.NotNil(t, err)
	assert.Contains(t, err.Error(), "BPF loader is unavailable")
}


func TestServer_setLoggerLevel_InvalidBody(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodPost, patternLoggers, bytes.NewReader([]byte("not-json")))
	w := httptest.NewRecorder()
	server.setLoggerLevel(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}


func TestServer_setLoggerLevel_InvalidLevel(t *testing.T) {
	server := &Server{}
	loggerInfo := LoggerInfo{Name: "status", Level: "invalidlevel"}
	body, _ := json.Marshal(loggerInfo)
	req := httptest.NewRequest(http.MethodPost, patternLoggers, bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.setLoggerLevel(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}


func TestPrintWorkloadDump(t *testing.T) {
	wd := WorkloadDump{
		Workloads: []*Workload{
			{Name: "z-workload"},
			{Name: "a-workload"},
		},
		Services: []*Service{
			{Name: "z-service"},
			{Name: "a-service"},
		},
		Policies: []*AuthorizationPolicy{
			{Name: "z-policy"},
			{Name: "a-policy"},
		},
	}
	w := httptest.NewRecorder()
	printWorkloadDump(w, wd)
	assert.Equal(t, http.StatusOK, w.Code)

	var result WorkloadDump
	err := json.Unmarshal(w.Body.Bytes(), &result)
	assert.Nil(t, err)
	assert.Equal(t, "a-workload", result.Workloads[0].Name)
	assert.Equal(t, "a-service", result.Services[0].Name)
	assert.Equal(t, "a-policy", result.Policies[0].Name)
}


func TestServer_StopServer(t *testing.T) {
	server := &Server{
		mux: http.NewServeMux(),
	}
	server.server = &http.Server{
		Addr:    "localhost:19999",
		Handler: server.mux,
	}
	server.StartServer()
	err := server.StopServer()
	assert.Nil(t, err)
}

func TestNewServer(t *testing.T) {
	xdsClient := &controller.XdsClient{}
	configs := &options.BootstrapConfigs{}
	server := NewServer(xdsClient, configs, nil)

	assert.NotNil(t, server)
	assert.NotNil(t, server.mux)
	assert.NotNil(t, server.server)
	assert.Equal(t, xdsClient, server.xdsClient)
	assert.Equal(t, configs, server.config)
	assert.Equal(t, adminAddr, server.server.Addr)
}

func TestPrintWorkloadBpfDump(t *testing.T) {
	dump := WorkloadBpfDump{}
	w := httptest.NewRecorder()
	printWorkloadBpfDump(w, dump)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Body.Bytes())
}

func TestServer_configDumpAds_NilAdsController(t *testing.T) {
	server := &Server{
		xdsClient: &controller.XdsClient{
			AdsController: nil,
		},
	}
	req := httptest.NewRequest(http.MethodGet, patternConfigDumpAds, nil)
	w := httptest.NewRecorder()
	server.configDumpAds(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), invalidModeErrMessage)
}

func TestServer_configDumpAds_NilClient(t *testing.T) {
	server := &Server{xdsClient: nil}
	req := httptest.NewRequest(http.MethodGet, patternConfigDumpAds, nil)
	w := httptest.NewRecorder()
	server.configDumpAds(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServer_setBpfLogLevel_NilLoader(t *testing.T) {
	server := &Server{loader: nil}
	w := httptest.NewRecorder()
	server.setBpfLogLevel(w, "info")
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestServer_setBpfLogLevel_InvalidLevel(t *testing.T) {
	server := &Server{loader: nil}
	w := httptest.NewRecorder()
	server.setBpfLogLevel(w, "superverbose")
	// nil loader triggers checkBpfLoader first
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestServer_bpfWorkloadMaps_NilController(t *testing.T) {
	server := &Server{
		xdsClient: &controller.XdsClient{
			WorkloadController: nil,
		},
	}
	req := httptest.NewRequest(http.MethodGet, patternBpfWorkloadMaps, nil)
	w := httptest.NewRecorder()
	server.bpfWorkloadMaps(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), invalidModeErrMessage)
}

func TestServer_bpfWorkloadMaps_NilClient(t *testing.T) {
	server := &Server{xdsClient: nil}
	req := httptest.NewRequest(http.MethodGet, patternBpfWorkloadMaps, nil)
	w := httptest.NewRecorder()
	server.bpfWorkloadMaps(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// Add these test functions to status_server_test.go

// ------------------------------------------------------------
// version handler — error path (can't easily trigger marshal
// error, but we can hit the success path more thoroughly)
// ------------------------------------------------------------
func TestServer_version_Success(t *testing.T) {
	server := &Server{}
	req := httptest.NewRequest(http.MethodGet, patternVersion, nil)
	w := httptest.NewRecorder()
	server.version(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
 
	// verify it returns valid JSON
	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	assert.Nil(t, err)
}

// ------------------------------------------------------------
// checkBpfLoader — loader with nil BpfKmesh and nil BpfWorkload
// ------------------------------------------------------------
func TestServer_checkBpfLoader_NilBpfObjects(t *testing.T) {
	server := &Server{loader: nil}
	w := httptest.NewRecorder()
	result := server.checkBpfLoader(w)
	assert.False(t, result)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ------------------------------------------------------------
// accesslogHandler — all branches
// ------------------------------------------------------------
func TestServer_accesslogHandler_AllBranches(t *testing.T) {
	// nil client → checkWorkloadMode fails
	t.Run("nil client", func(t *testing.T) {
		server := &Server{xdsClient: nil}
		req := httptest.NewRequest(http.MethodPost, patternAccesslog+"?enable=true", nil)
		w := httptest.NewRecorder()
		server.accesslogHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	// nil WorkloadController → checkWorkloadMode fails
	t.Run("nil WorkloadController", func(t *testing.T) {
		server := &Server{
			xdsClient: &controller.XdsClient{WorkloadController: nil},
		}
		req := httptest.NewRequest(http.MethodPost, patternAccesslog+"?enable=true", nil)
		w := httptest.NewRecorder()
		server.accesslogHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	// invalid bool param
	t.Run("invalid bool param", func(t *testing.T) {
		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: nil,
		}
		req := httptest.NewRequest(http.MethodPost, patternAccesslog+"?enable=notabool", nil)
		w := httptest.NewRecorder()
		server.accesslogHandler(w, req)
		// nil loader → checkBpfLoader fails first
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
 
// ------------------------------------------------------------
// monitoringHandler — all branches
// ------------------------------------------------------------
func TestServer_monitoringHandler_AllBranches(t *testing.T) {
	// invalid method
	t.Run("invalid method", func(t *testing.T) {
		server := &Server{}
		req := httptest.NewRequest(http.MethodGet, patternMonitoring, nil)
		w := httptest.NewRecorder()
		server.monitoringHandler(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
 
	// nil client
	t.Run("nil client", func(t *testing.T) {
		server := &Server{xdsClient: nil}
		req := httptest.NewRequest(http.MethodPost, patternMonitoring+"?enable=true", nil)
		w := httptest.NewRecorder()
		server.monitoringHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
 
	// invalid bool param
	t.Run("invalid bool param", func(t *testing.T) {
		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: nil,
		}
		req := httptest.NewRequest(http.MethodPost, patternMonitoring+"?enable=notabool", nil)
		w := httptest.NewRecorder()
		server.monitoringHandler(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
 
// ------------------------------------------------------------
// workloadMetricHandler — all branches
// ------------------------------------------------------------
func TestServer_workloadMetricHandler_AllBranches(t *testing.T) {
	// nil client
	t.Run("nil client", func(t *testing.T) {
		server := &Server{xdsClient: nil}
		req := httptest.NewRequest(http.MethodPost, patternWorkloadMetrics+"?enable=true", nil)
		w := httptest.NewRecorder()
		server.workloadMetricHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
 
	// invalid bool param
	t.Run("invalid bool param", func(t *testing.T) {
		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: nil,
		}
		req := httptest.NewRequest(http.MethodPost, patternWorkloadMetrics+"?enable=notabool", nil)
		w := httptest.NewRecorder()
		server.workloadMetricHandler(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
 
// ------------------------------------------------------------
// connectionMetricHandler — all branches
// ------------------------------------------------------------
func TestServer_connectionMetricHandler_AllBranches(t *testing.T) {
	// nil client
	t.Run("nil client", func(t *testing.T) {
		server := &Server{xdsClient: nil}
		req := httptest.NewRequest(http.MethodPost, patternConnectionMetrics+"?enable=true", nil)
		w := httptest.NewRecorder()
		server.connectionMetricHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
 
	// invalid bool param
	t.Run("invalid bool param", func(t *testing.T) {
		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: nil,
		}
		req := httptest.NewRequest(http.MethodPost, patternConnectionMetrics+"?enable=notabool", nil)
		w := httptest.NewRecorder()
		server.connectionMetricHandler(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
 
// ------------------------------------------------------------
// authzHandler — all branches
// ------------------------------------------------------------
func TestServer_authzHandler_AllBranches(t *testing.T) {
	// nil client
	t.Run("nil client", func(t *testing.T) {
		server := &Server{xdsClient: nil}
		req := httptest.NewRequest(http.MethodPost, patternAuthz+"?enable=true", nil)
		w := httptest.NewRecorder()
		server.authzHandler(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
 
	// invalid bool param with valid client but nil loader
	t.Run("invalid bool param", func(t *testing.T) {
		server := &Server{
			xdsClient: &controller.XdsClient{
				WorkloadController: &workload.Controller{
					MetricController: &telemetry.MetricController{},
				},
			},
			loader: nil,
		}
		req := httptest.NewRequest(http.MethodPost, patternAuthz+"?enable=notabool", nil)
		w := httptest.NewRecorder()
		server.authzHandler(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
 
// ------------------------------------------------------------
// getLoggerLevel — all branches
// ------------------------------------------------------------
func TestServer_getLoggerLevel_AllBranches(t *testing.T) {
	server := &Server{loader: nil}
 
	// invalid logger name
	t.Run("invalid logger name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, patternLoggers+"?name=nonexistent_logger_xyz", nil)
		w := httptest.NewRecorder()
		server.getLoggerLevel(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
 
	// bpf logger name with nil loader
	t.Run("bpf logger nil loader", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, patternLoggers+"?name="+bpfLoggerName, nil)
		w := httptest.NewRecorder()
		server.getLoggerLevel(w, req)
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
 
// ------------------------------------------------------------
// setLoggerLevel — bpf logger with nil loader
// ------------------------------------------------------------
func TestServer_setLoggerLevel_BpfLogger(t *testing.T) {
	server := &Server{loader: nil}
	loggerInfo := LoggerInfo{Name: bpfLoggerName, Level: "info"}
	body, _ := json.Marshal(loggerInfo)
	req := httptest.NewRequest(http.MethodPost, patternLoggers, bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.setLoggerLevel(w, req)
	// nil loader → checkBpfLoader fails
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
 
// ------------------------------------------------------------
// setBpfLogLevel — all branches (without BPF loader)
// ------------------------------------------------------------
func TestServer_setBpfLogLevel_AllBranches(t *testing.T) {
	// nil loader
	t.Run("nil loader", func(t *testing.T) {
		server := &Server{loader: nil}
		w := httptest.NewRecorder()
		server.setBpfLogLevel(w, "info")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
 
	// invalid string level not in map
	t.Run("unknown level string", func(t *testing.T) {
		server := &Server{loader: nil}
		w := httptest.NewRecorder()
		server.setBpfLogLevel(w, "unknown")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}
 
// ------------------------------------------------------------
// getBpfLogLevel — nil loader branch
// ------------------------------------------------------------
func TestServer_getBpfLogLevel_AllBranches(t *testing.T) {
	t.Run("nil loader", func(t *testing.T) {
		server := &Server{loader: nil}
		info, err := server.getBpfLogLevel()
		assert.Nil(t, info)
		assert.NotNil(t, err)
	})
}
 
// ------------------------------------------------------------
// getLoggerNames — success path
// ------------------------------------------------------------
func TestServer_getLoggerNames(t *testing.T) {
	server := &Server{}
	w := httptest.NewRecorder()
	server.getLoggerNames(w)
	assert.Equal(t, http.StatusOK, w.Code)
 
	var names []string
	err := json.Unmarshal(w.Body.Bytes(), &names)
	assert.Nil(t, err)
	assert.Contains(t, names, bpfLoggerName)
}
 
// ------------------------------------------------------------
// printWorkloadBpfDump — success path
// ------------------------------------------------------------
func TestPrintWorkloadBpfDump_Success(t *testing.T) {
	dump := WorkloadBpfDump{}
	w := httptest.NewRecorder()
	printWorkloadBpfDump(w, dump)
	assert.Equal(t, http.StatusOK, w.Code)
 
	var result map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &result)
	assert.Nil(t, err)
}
 
// ------------------------------------------------------------
// configDumpAds — nil xdsClient
// ------------------------------------------------------------
func TestServer_configDumpAds_WithAdsController(t *testing.T) {
	server := &Server{xdsClient: nil}
	req := httptest.NewRequest(http.MethodGet, patternConfigDumpAds, nil)
	w := httptest.NewRecorder()
	server.configDumpAds(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
 
// ------------------------------------------------------------
// bpfAdsMaps — nil AdsController
// ------------------------------------------------------------
func TestServer_bpfAdsMaps_NilController(t *testing.T) {
	server := &Server{
		xdsClient: &controller.XdsClient{
			AdsController: nil,
		},
	}
	req := httptest.NewRequest(http.MethodGet, patternBpfAdsMaps, nil)
	w := httptest.NewRecorder()
	server.bpfAdsMaps(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), invalidModeErrMessage)
}
 
// ------------------------------------------------------------
// printWorkloadDump — error path via empty dump
// ------------------------------------------------------------
func TestPrintWorkloadDump_Empty(t *testing.T) {
	wd := WorkloadDump{
		Workloads: []*Workload{},
		Services:  []*Service{},
		Policies:  []*AuthorizationPolicy{},
	}
	w := httptest.NewRecorder()
	printWorkloadDump(w, wd)
	assert.Equal(t, http.StatusOK, w.Code)
 
	var result WorkloadDump
	err := json.Unmarshal(w.Body.Bytes(), &result)
	assert.Nil(t, err)
	assert.Empty(t, result.Workloads)
	assert.Empty(t, result.Services)
	assert.Empty(t, result.Policies)
}