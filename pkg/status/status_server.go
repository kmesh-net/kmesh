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

	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	bpfads "kmesh.net/kmesh/pkg/bpf/ads"
	maps_v2 "kmesh.net/kmesh/pkg/cache/v2/maps"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/ads"
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
	patternWorkloadMetrics    = "/workload_metrics"
	patternAuthz              = "/authz"

	bpfLoggerName = "bpf"

	httpTimeout = time.Second * 20

	invalidModeErrMessage = "\tInvalid Client Mode\n"
)

type Server struct {
	config    *options.BootstrapConfigs
	xdsClient *controller.XdsClient
	mux       *http.ServeMux
	server    *http.Server
	loader    *bpf.BpfLoader
}

func NewServer(c *controller.XdsClient, configs *options.BootstrapConfigs, loader *bpf.BpfLoader) *Server {
	s := &Server{
		config:    configs,
		xdsClient: c,
		mux:       http.NewServeMux(),
		loader:    loader,
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
	s.mux.HandleFunc(patternWorkloadMetrics, s.workloadMetricHandler)
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

func (s *Server) bpfWorkloadMaps(w http.ResponseWriter, r *http.Request) {
	if !s.checkWorkloadMode(w) {
		return
	}
	client := s.xdsClient
	bpfMaps := client.WorkloadController.Processor.GetBpfCache()
	workloadBpfDump := NewWorkloadBpfDump(s.xdsClient.WorkloadController.Processor.GetHashName()).
		WithBackends(bpfMaps.BackendLookupAll()).
		WithEndpoints(bpfMaps.EndpointLookupAll()).
		WithFrontends(bpfMaps.FrontendLookupAll()).
		WithServices(bpfMaps.ServiceLookupAll()).
		WithWorkloadPolicies(bpfMaps.WorkloadPolicyLookupAll())

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

	if s.loader.GetEnableMonitoring() == constants.DISABLED && enabled {
		http.Error(w, "Kmesh monitoring is disabled, cannot enable accesslog.", http.StatusBadRequest)
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
	var enableMonitoring uint32
	if enabled {
		enableMonitoring = constants.ENABLED
	} else {
		enableMonitoring = constants.DISABLED
	}
	if err := s.loader.UpdateEnableMonitoring(enableMonitoring); err != nil {
		http.Error(w, fmt.Sprintf("update bpf monitoring failed: %v", err), http.StatusBadRequest)
		return
	}

	s.xdsClient.WorkloadController.SetMonitoringTrigger(enabled)
	s.xdsClient.WorkloadController.SetAccesslogTrigger(enabled)
	s.xdsClient.WorkloadController.SetWorkloadMetricTrigger(enabled)
	w.WriteHeader(http.StatusOK)
}

func (s *Server) workloadMetricHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	info := r.URL.Query().Get("enable")
	enabled, err := strconv.ParseBool(info)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("invalid accesslog enable=%s", info)))
		return
	}

	if s.loader.GetEnableMonitoring() == constants.DISABLED && enabled {
		http.Error(w, "Kmesh monitoring is disabled, cannot enable workload metrics.", http.StatusBadRequest)
		return
	}

	s.xdsClient.WorkloadController.SetWorkloadMetricTrigger(enabled)
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
	var authzOffload uint32
	if enabled {
		authzOffload = constants.ENABLED
	} else {
		authzOffload = constants.DISABLED
	}
	if err := s.loader.UpdateAuthzOffload(authzOffload); err != nil {
		http.Error(w, fmt.Sprintf("update bpf authz failed: %v", err), http.StatusBadRequest)
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
	Workloads []*Workload            `json:"workloads"`
	Services  []*Service             `json:"services"`
	Policies  []*AuthorizationPolicy `json:"policies"`
}

func (s *Server) configDumpWorkload(w http.ResponseWriter, r *http.Request) {
	if !s.checkWorkloadMode(w) {
		return
	}

	client := s.xdsClient

	workloads := client.WorkloadController.Processor.WorkloadCache.List()
	services := client.WorkloadController.Processor.ServiceCache.List()
	policies := client.WorkloadController.Rbac.PoliciesList()
	workloadDump := WorkloadDump{
		Workloads: make([]*Workload, 0, len(workloads)),
		Services:  make([]*Service, 0, len(services)),
		Policies:  make([]*AuthorizationPolicy, 0, len(policies)),
	}
	for _, w := range workloads {
		workloadDump.Workloads = append(workloadDump.Workloads, ConvertWorkload(w))
	}
	for _, s := range services {
		workloadDump.Services = append(workloadDump.Services, ConvertService(s))
	}
	for _, p := range policies {
		workloadDump.Policies = append(workloadDump.Policies, ConvertAuthorizationPolicy(p))
	}
	printWorkloadDump(w, workloadDump)
}

func (s *Server) readyProbe(w http.ResponseWriter, r *http.Request) {
	// TODO: Add some components check
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func (s *Server) getBpfLogLevel() (*LoggerInfo, error) {
	logLevel := s.loader.GetBpfLogLevel()
	logLevelMap := map[int]string{
		constants.BPF_LOG_ERR:   "error",
		constants.BPF_LOG_WARN:  "warn",
		constants.BPF_LOG_INFO:  "info",
		constants.BPF_LOG_DEBUG: "debug",
	}

	loggerLevel, exists := logLevelMap[int(logLevel)]
	if !exists {
		return nil, fmt.Errorf("unexpected invalid log level: %d", logLevel)
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

	if err := s.loader.UpdateBpfLogLevel(uint32(level)); err != nil {
		http.Error(w, fmt.Sprintf("update bpf log level error: %v", err), http.StatusBadRequest)
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
