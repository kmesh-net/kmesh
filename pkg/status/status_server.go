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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"github.com/cilium/ebpf"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/api/v2/workloadapi/security"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	bpfads "kmesh.net/kmesh/pkg/bpf/ads"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/ads"
	"kmesh.net/kmesh/pkg/controller/workload/bpfcache"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var log = logger.NewLoggerScope("status")

const (
	adminAddr = "localhost:15200"

	patternVersion            = "/version"
	patternBpfAdsMaps         = "/debug/config_dump/bpf/kernel-native"
	patternBpfWorkloadMaps    = "/debug/config_dump/bpf/dual-engine"
	configDumpPrefix          = "/debug/config_dump"
	patternConfigDumpAds      = configDumpPrefix + "/kernel-native"
	patternConfigDumpWorkload = configDumpPrefix + "/dual-engine"
	patternReadyProbe         = "/debug/ready"
	patternLoggers            = "/debug/loggers"
	patternAccesslog          = "/accesslog"
	patternMonitoring         = "/monitoring"
	patternAuthz              = "/authz"

	bpfLoggerName = "bpf"

	httpTimeout = time.Second * 20

	invalidModeErrMessage = "\tInvalid Client Mode\n"
)

type Server struct {
	config         *options.BootstrapConfigs
	xdsClient      *controller.XdsClient
	mux            *http.ServeMux
	server         *http.Server
	kmeshConfigMap *ebpf.Map
}

func NewServer(c *controller.XdsClient, configs *options.BootstrapConfigs, configMap *ebpf.Map) *Server {
	s := &Server{
		config:         configs,
		xdsClient:      c,
		mux:            http.NewServeMux(),
		kmeshConfigMap: configMap,
	}
	s.server = &http.Server{
		Addr:         adminAddr,
		Handler:      s.mux,
		ReadTimeout:  httpTimeout,
		WriteTimeout: httpTimeout,
	}

	s.mux.HandleFunc(patternVersion, s.version)
	s.mux.HandleFunc(patternBpfAdsMaps, s.bpfAdsMaps)
	s.mux.HandleFunc(patternBpfWorkloadMaps, s.bpfWorkloadMaps)
	s.mux.HandleFunc(patternConfigDumpAds, s.configDumpAds)
	s.mux.HandleFunc(patternConfigDumpWorkload, s.configDumpWorkload)
	s.mux.HandleFunc(patternLoggers, s.loggersHandler)
	s.mux.HandleFunc(patternAccesslog, s.accesslogHandler)
	s.mux.HandleFunc(patternMonitoring, s.monitoringHandler)
	s.mux.HandleFunc(patternAuthz, s.authzHandler)

	// TODO: add dump certificate, authorizationPolicies and services
	s.mux.HandleFunc(patternReadyProbe, s.readyProbe)

	// support pprof
	s.mux.HandleFunc("/debug/pprof/", pprof.Index)
	s.mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	s.mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	s.mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	s.mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	return s
}

func (s *Server) version(w http.ResponseWriter, r *http.Request) {
	v := version.Get()

	data, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		log.Errorf("Failed to marshal version info: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) checkWorkloadMode(w http.ResponseWriter) bool {
	client := s.xdsClient
	if client == nil || client.WorkloadController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, invalidModeErrMessage)
		return false
	}
	return true
}

func (s *Server) checkAdsMode(w http.ResponseWriter) bool {
	client := s.xdsClient
	if client == nil || client.AdsController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, invalidModeErrMessage)
		return false
	}
	return true
}

type WorkloadBpfDump struct {
	WorkloadPolicies []bpfcache.WorkloadPolicyValue
	Backends         []bpfcache.BackendValue
	Endpoints        []bpfcache.EndpointValue
	Frontends        []bpfcache.FrontendValue
	Services         []bpfcache.ServiceValue
}

func (s *Server) bpfWorkloadMaps(w http.ResponseWriter, r *http.Request) {
	if !s.checkWorkloadMode(w) {
		return
	}
	client := s.xdsClient
	bpfMaps := client.WorkloadController.Processor.GetBpfCache()
	workloadBpfDump := WorkloadBpfDump{
		WorkloadPolicies: bpfMaps.WorkloadPolicyLookupAll(),
		Backends:         bpfMaps.BackendLookupAll(),
		Endpoints:        bpfMaps.EndpointLookupAll(),
		Frontends:        bpfMaps.FrontendLookupAll(),
		Services:         bpfMaps.ServiceLookupAll(),
	}
	printWorkloadBpfDump(w, workloadBpfDump)
}

func printWorkloadBpfDump(w http.ResponseWriter, wbd WorkloadBpfDump) {
	data, err := json.MarshalIndent(wbd, "", "    ")
	if err != nil {
		log.Errorf("Failed to marshal WorkloadBpfDump: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) bpfAdsMaps(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdsMode(w) {
		return
	}
	var err error
	dynamicRes := &adminv2.ConfigResources{}
	dynamicRes.ClusterConfigs, err = maps_v2.ClusterLookupAll()
	if err != nil {
		log.Errorf("ClusterLookupAll failed: %v", err)
	}
	dynamicRes.ListenerConfigs, err = maps_v2.ListenerLookupAll()
	if err != nil {
		log.Errorf("ListenerLookupAll failed: %v", err)
	}
	if bpfads.AdsL7Enabled() {
		dynamicRes.RouteConfigs, err = maps_v2.RouteConfigLookupAll()
		if err != nil {
			log.Errorf("RouteConfigLookupAll failed: %v", err)
		}
	}
	ads.SetApiVersionInfo(dynamicRes)

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, protojson.Format(&adminv2.ConfigDump{
		DynamicResources: dynamicRes,
	}))
}

type LoggerInfo struct {
	Name  string `json:"name,omitempty"`
	Level string `json:"level,omitempty"`
}

func (s *Server) loggersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.getLoggerLevel(w, r)
	} else if r.Method == http.MethodPost {
		s.setLoggerLevel(w, r)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) accesslogHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	accesslogInfo := r.URL.Query().Get("enable")
	enabled, err := strconv.ParseBool(accesslogInfo)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("invalid accesslog enable=%s", accesslogInfo)))
		return
	}

	configMap, err := bpf.GetKmeshConfigMap(s.kmeshConfigMap)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get kmeshConfigMap: %v", err), http.StatusBadRequest)
		return
	}
	if configMap.EnableMonitoring == constants.DISABLED && enabled {
		http.Error(w, "Kmesh monitoring is disable, cannot enable accesslog.", http.StatusBadRequest)
		return
	}

	s.xdsClient.WorkloadController.SetAccesslogTrigger(enabled)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) monitoringHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	info := r.URL.Query().Get("enable")
	enabled, err := strconv.ParseBool(info)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("invalid monitoring enable=%s", info)))
		return
	}
	configMap, err := bpf.GetKmeshConfigMap(s.kmeshConfigMap)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to get KmeshConfigMap: %v", err), http.StatusBadRequest)
		return
	}

	if enabled {
		configMap.EnableMonitoring = constants.ENABLED
	} else {
		configMap.EnableMonitoring = constants.DISABLED
	}
	if err := bpf.UpdateKmeshConfigMap(s.kmeshConfigMap, configMap); err != nil {
		http.Error(w, fmt.Sprintf("update monitoring in KmeshConfigMap failed: %v", err), http.StatusBadRequest)
		return
	}

	s.xdsClient.WorkloadController.SetMonitoringTrigger(enabled)
	s.xdsClient.WorkloadController.SetAccesslogTrigger(enabled)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) authzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	authzInfo := r.URL.Query().Get("enable")
	enabled, err := strconv.ParseBool(authzInfo)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("invalid authz enable=%s", authzInfo)))
		return
	}

	configMap, err := bpf.GetKmeshConfigMap(s.kmeshConfigMap)
	if err != nil {
		http.Error(w, fmt.Sprintf("update authz in KmeshConfigMap failed: %v", err), http.StatusBadRequest)
		return
	}
	if enabled {
		configMap.AuthzOffload = constants.ENABLED
	} else {
		configMap.AuthzOffload = constants.DISABLED
	}
	if err := bpf.UpdateKmeshConfigMap(s.kmeshConfigMap, configMap); err != nil {
		http.Error(w, fmt.Sprintf("update authz in KmeshConfigMap failed: %v", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (s *Server) getLoggerNames(w http.ResponseWriter) {
	loggerNames := append(logger.GetLoggerNames(), bpfLoggerName)
	data, err := json.MarshalIndent(&loggerNames, "", "    ")
	if err != nil {
		log.Errorf("Failed to marshal logger names: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(data)
}

func (s *Server) getLoggerLevel(w http.ResponseWriter, r *http.Request) {
	loggerName := r.URL.Query().Get("name")
	if loggerName == "" {
		s.getLoggerNames(w)
		return
	}
	var loggerInfo *LoggerInfo
	if loggerName != bpfLoggerName {
		loggerLevel, err := logger.GetLoggerLevel(loggerName)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintf(w, "\t%v\n", err)
			return
		}
		loggerInfo = &LoggerInfo{
			Name:  loggerName,
			Level: loggerLevel.String(),
		}
	} else {
		var err error
		loggerInfo, err = s.getBpfLogLevel()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	data, err := json.MarshalIndent(&loggerInfo, "", "    ")
	if err != nil {
		log.Errorf("Failed to marshal logger info: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Server) setLoggerLevel(w http.ResponseWriter, r *http.Request) {
	var (
		loggerInfo  LoggerInfo
		loggerLevel logrus.Level
	)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s: %v\n", "Error reading request body", err)
		return
	}

	if err = json.Unmarshal(body, &loggerInfo); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s: %v\n", "Invalid request body format", err)
		return
	}

	if loggerInfo.Name == bpfLoggerName {
		s.setBpfLogLevel(w, loggerInfo.Level)
		return
	}

	if loggerLevel, err = logrus.ParseLevel(loggerInfo.Level); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s: %v\n", "Invalid request body format", err)
		return
	}

	if err = logger.SetLoggerLevel(loggerInfo.Name, loggerLevel); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%v\n", err)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) configDumpAds(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdsMode(w) {
		return
	}

	client := s.xdsClient
	w.WriteHeader(http.StatusOK)
	cache := client.AdsController.Processor.Cache
	dynamicRes := &adminv2.ConfigResources{}

	dynamicRes.ClusterConfigs = cache.ClusterCache.Dump()
	dynamicRes.ListenerConfigs = cache.ListenerCache.Dump()
	dynamicRes.RouteConfigs = cache.RouteCache.Dump()
	ads.SetApiVersionInfo(dynamicRes)

	fmt.Fprintln(w, protojson.Format(&adminv2.ConfigDump{
		DynamicResources: dynamicRes,
	}))
}

type WorkloadDump struct {
	Workloads []*Workload
	Services  []*Service
	// TODO: add authorization
	Policies []*security.Authorization
}

func (s *Server) configDumpWorkload(w http.ResponseWriter, r *http.Request) {
	if !s.checkWorkloadMode(w) {
		return
	}

	client := s.xdsClient

	workloads := client.WorkloadController.Processor.WorkloadCache.List()
	services := client.WorkloadController.Processor.ServiceCache.List()
	workloadDump := WorkloadDump{
		Workloads: make([]*Workload, 0, len(workloads)),
		Services:  make([]*Service, 0, len(services)),
	}
	for _, w := range workloads {
		workloadDump.Workloads = append(workloadDump.Workloads, ConvertWorkload(w))
	}
	for _, s := range services {
		workloadDump.Services = append(workloadDump.Services, ConvertService(s))
	}
	printWorkloadDump(w, workloadDump)
}

func (s *Server) readyProbe(w http.ResponseWriter, r *http.Request) {
	// TODO: Add some components check
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) getBpfLogLevel() (*LoggerInfo, error) {
	config, err := bpf.GetKmeshConfigMap(s.kmeshConfigMap)
	if err != nil {
		return nil, fmt.Errorf("get log level error: %v", err)
	}

	logLevel := config.BpfLogLevel

	logLevelMap := map[int]string{
		constants.BPF_LOG_ERR:   "error",
		constants.BPF_LOG_WARN:  "warn",
		constants.BPF_LOG_INFO:  "info",
		constants.BPF_LOG_DEBUG: "debug",
	}

	loggerLevel, exists := logLevelMap[int(logLevel)]
	if !exists {
		return nil, fmt.Errorf("unexpected invalid log level: %d", config.BpfLogLevel)
	}

	return &LoggerInfo{
		Name:  bpfLoggerName,
		Level: loggerLevel,
	}, nil
}

func (s *Server) setBpfLogLevel(w http.ResponseWriter, levelStr string) {
	level, err := strconv.Atoi(levelStr)
	if err != nil {
		logLevelMap := map[string]int{
			"error": constants.BPF_LOG_ERR,
			"warn":  constants.BPF_LOG_WARN,
			"info":  constants.BPF_LOG_INFO,
			"debug": constants.BPF_LOG_DEBUG,
		}
		var exists bool
		if level, exists = logLevelMap[levelStr]; !exists {
			http.Error(w, "Invalid log level", http.StatusBadRequest)
			return
		}
	}
	if level < constants.BPF_LOG_ERR || level > constants.BPF_LOG_DEBUG {
		http.Error(w, "Invalid log level", http.StatusBadRequest)
		return
	}

	// Because kmesh config has pod gateway and node ip data.
	// When change the log level, need to make sure that the pod gateway and node ip remain unchanged.
	config, err := bpf.GetKmeshConfigMap(s.kmeshConfigMap)
	if err != nil {
		http.Error(w, fmt.Sprintf("get kmesh config error: %v", err), http.StatusBadRequest)
		return
	}
	config.BpfLogLevel = uint32(level)
	if err := bpf.UpdateKmeshConfigMap(s.kmeshConfigMap, config); err != nil {
		http.Error(w, fmt.Sprintf("update log level error: %v", err), http.StatusBadRequest)
		return
	}
	fmt.Fprintf(w, "set BPF Log Level: %d\n", level)
}

func (s *Server) StartServer() {
	go func() {
		err := s.server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Errorf("Failed to start status server: %v", err)
		}
	}()
}

func (s *Server) StopServer() error {
	return s.server.Close()
}

func printWorkloadDump(w http.ResponseWriter, wd WorkloadDump) {
	data, err := json.MarshalIndent(wd, "", "    ")
	if err != nil {
		log.Errorf("Failed to marshal WorkloadDump: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}
