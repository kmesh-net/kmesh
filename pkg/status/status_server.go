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
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	// nolint
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/ads"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("status")

const (
	adminAddr = "localhost:15200"

	patternHelp               = "/help"
	patternOptions            = "/options"
	patternBpfAdsMaps         = "/debug/bpf/ads"
	configDumpPrefix          = "/debug/config_dump"
	patternConfigDumpAds      = configDumpPrefix + "/ads"
	patternConfigDumpWorkload = configDumpPrefix + "/workload"
	patternReadyProbe         = "/debug/ready"

	httpTimeout = time.Second * 20
)

type Server struct {
	config     *options.BootstrapConfigs
	controller *controller.Controller
	mux        *http.ServeMux
	server     *http.Server
}

func NewServer(c *controller.Controller, configs *options.BootstrapConfigs) *Server {
	s := &Server{
		config:     configs,
		controller: c,
		mux:        http.NewServeMux(),
	}
	s.server = &http.Server{
		Addr:         adminAddr,
		Handler:      s.mux,
		ReadTimeout:  httpTimeout,
		WriteTimeout: httpTimeout,
	}

	s.mux.HandleFunc(patternHelp, s.httpHelp)
	s.mux.HandleFunc(patternOptions, s.httpOptions)
	s.mux.HandleFunc(patternBpfAdsMaps, s.bpfAdsMaps)
	s.mux.HandleFunc(patternConfigDumpAds, s.configDumpAds)
	s.mux.HandleFunc(patternConfigDumpWorkload, s.configDumpWorkload)
	// TODO: add dump certificate, authorizationPolicies and services
	s.mux.HandleFunc(patternReadyProbe, s.readyProbe)
	return s
}

func (s *Server) httpHelp(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "\t%s: %s\n", patternHelp,
		"print list of commands")
	fmt.Fprintf(w, "\t%s: %s\n", patternOptions,
		"print config options")
	fmt.Fprintf(w, "\t%s: %s\n", patternBpfAdsMaps,
		"print bpf kmesh maps in kernel")
	fmt.Fprintf(w, "\t%s: %s\n", patternConfigDumpAds,
		"dump xDS[Listener, Route, Cluster] configurations")
	fmt.Fprintf(w, "\t%s: %s\n", patternConfigDumpWorkload,
		"dump workload configurations")
}

func (s *Server) httpOptions(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, s.config.String())
}

func (s *Server) bpfAdsMaps(w http.ResponseWriter, r *http.Request) {
	client := s.controller.GetXdsClient()
	if client == nil || client.AdsController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	}

	w.WriteHeader(http.StatusOK)
	cache := client.AdsController.Processor.Cache
	dynamicRes := &adminv2.ConfigResources{}

	dynamicRes.ClusterConfigs = cache.ClusterCache.DumpBpf()
	dynamicRes.ListenerConfigs = cache.ListenerCache.DumpBpf()
	dynamicRes.RouteConfigs = cache.RouteCache.DumpBpf()
	ads.SetApiVersionInfo(dynamicRes)

	fmt.Fprintln(w, protojson.Format(&adminv2.ConfigDump{
		DynamicResources: dynamicRes,
	}))
}

func (s *Server) configDumpAds(w http.ResponseWriter, r *http.Request) {
	client := s.controller.GetXdsClient()
	if client == nil || client.AdsController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	}

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

func (s *Server) configDumpWorkload(w http.ResponseWriter, r *http.Request) {
	client := s.controller.GetXdsClient()
	if client == nil || client.WorkloadController == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	}

	w.WriteHeader(http.StatusOK)
	workloads := client.WorkloadController.Processor.WorkloadCache.List()
	data, _ := Marshal(workloads)
	fmt.Fprintln(w, string(data))
}

func (s *Server) readyProbe(w http.ResponseWriter, r *http.Request) {
	// TODO: Add some components check
	w.WriteHeader(http.StatusOK)
}

func (s *Server) StartServer() {
	go func() {
		err := s.server.ListenAndServe()
		if err != nil {
			log.Errorf("Failed to start status server: %v", err)
		}
	}()
}

func (s *Server) StopServer() error {
	return s.server.Close()
}

// Marshal marshals a slice of proto messages to json.
func Marshal[S ~[]E, E proto.Message](s S) ([]byte, error) {
	raw := make([]json.RawMessage, len(s))
	for i, w := range s {
		data, err := marshalWithIndent(w)
		if err != nil {
			return nil, err
		}
		raw[i] = data
	}
	return json.MarshalIndent(raw, "", "  ")
}

// marshalWithIndent marshals a proto message with indent to json.
func marshalWithIndent(msg proto.Message) ([]byte, error) {
	return protojson.MarshalOptions{
		Multiline: true,
		Indent:    "  ",
	}.Marshal(msg)
}
