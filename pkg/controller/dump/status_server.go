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

package dump

import (
	"fmt"
	"net/http"
	"time"

	"kmesh.net/kmesh/pkg/controller/ads"

	// nolint
	"google.golang.org/protobuf/encoding/protojson"

	admin_v2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/controller"
)

const (
	adminAddr = "localhost:15200"

	patternHelp            = "/help"
	patternOptions         = "/options"
	patternBpfKmeshMaps    = "/bpf/kmesh/maps"
	patternControllerEnvoy = "/controller/envoy"

	httpTimeout = time.Second * 20
)

type StatusServer struct {
	config     *options.BootstrapConfigs
	controller *controller.Controller
	mux        *http.ServeMux
	server     *http.Server
}

func NewStatusServer(c *controller.Controller, configs *options.BootstrapConfigs) *StatusServer {
	s := &StatusServer{
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
	s.mux.HandleFunc(patternBpfKmeshMaps, s.httpBpfKmeshMaps)
	s.mux.HandleFunc(patternControllerEnvoy, s.httpControllerEnvoy)

	return s
}

func (s *StatusServer) httpHelp(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	fmt.Fprintf(w, "\t%s: %s\n", patternHelp,
		"print list of commands")
	fmt.Fprintf(w, "\t%s: %s\n", patternOptions,
		"print config options")
	fmt.Fprintf(w, "\t%s: %s\n", patternBpfKmeshMaps,
		"print bpf kmesh maps in kernel")
	fmt.Fprintf(w, "\t%s: %s\n", patternControllerEnvoy,
		"print control-plane in envoy cache")
}

func (s *StatusServer) httpOptions(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, s.config.String())
}

func (s *StatusServer) httpBpfKmeshMaps(w http.ResponseWriter, r *http.Request) {
	client := s.controller.GetXdsClient()
	if client == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	} else if client.AdsController.Processor == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "none client.processor")
		return
	}

	switch r.Method {
	case http.MethodGet:
		dynamicLd := client.AdsController.Processor.Cache
		dynamicRes := &admin_v2.ConfigResources{}

		dynamicRes.ClusterConfigs = append(dynamicRes.ClusterConfigs, dynamicLd.ClusterCache.StatusLookup()...)
		dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusLookup()...)
		dynamicRes.RouteConfigs = append(dynamicRes.RouteConfigs, dynamicLd.RouteCache.StatusLookup()...)
		ads.SetApiVersionInfo(dynamicRes)

		fmt.Fprintln(w, protojson.Format(&admin_v2.ConfigDump{
			DynamicResources: dynamicRes,
		}))
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (s *StatusServer) httpControllerEnvoy(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	client := s.controller.GetXdsClient()
	if client == nil {
		fmt.Fprintf(w, "\t%s\n", "invalid bpf.BpfConfig.ClientMode")
		return
	}
	dynamicLd := client.AdsController.Processor.Cache
	dynamicRes := &admin_v2.ConfigResources{}

	dynamicRes.ClusterConfigs = append(dynamicRes.ClusterConfigs, dynamicLd.ClusterCache.StatusRead()...)
	dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusRead()...)
	dynamicRes.RouteConfigs = append(dynamicRes.RouteConfigs, dynamicLd.RouteCache.StatusRead()...)
	ads.SetApiVersionInfo(dynamicRes)

	fmt.Fprintln(w, protojson.Format(&admin_v2.ConfigDump{
		DynamicResources: dynamicRes,
	}))
}

func (s *StatusServer) StartServer() {
	go func() {
		// TODO: handle the error
		_ = s.server.ListenAndServe()
	}()
}

func (s *StatusServer) StopServer() error {
	return s.server.Close()
}
