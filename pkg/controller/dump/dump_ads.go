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

	// nolint
	"google.golang.org/protobuf/encoding/protojson"

	admin_v2 "kmesh.net/kmesh/api/v2/admin"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/envoy"
	"kmesh.net/kmesh/pkg/options"
)

const (
	adminAddr = "localhost:15200"

	patternHelp            = "/help"
	patternOptions         = "/options"
	patternBpfKmeshMaps    = "/bpf/kmesh/maps"
	patternControllerEnvoy = "/controller/envoy"

	httpTimeout = time.Second * 20
)

type httpServer struct {
	mux    *http.ServeMux
	server *http.Server
}

func newHttpServer() *httpServer {
	s := &httpServer{
		mux: http.NewServeMux(),
	}
	s.server = &http.Server{
		Addr:         adminAddr,
		Handler:      s.mux,
		ReadTimeout:  httpTimeout,
		WriteTimeout: httpTimeout,
	}

	s.mux.HandleFunc(patternHelp, httpHelp)
	s.mux.HandleFunc(patternOptions, httpOptions)
	s.mux.HandleFunc(patternBpfKmeshMaps, httpBpfKmeshMaps)
	s.mux.HandleFunc(patternControllerEnvoy, httpControllerEnvoy)

	return s
}

func httpHelp(w http.ResponseWriter, r *http.Request) {
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

func httpOptions(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, options.String())
}

func httpBpfKmeshMaps(w http.ResponseWriter, r *http.Request) {
	client := controller.GetXdsClient()
	if client == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	} else if client.AdsStream.Event == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "none client.Event")
		return
	}

	switch r.Method {
	case http.MethodGet:
		dynamicLd := client.AdsStream.Event.DynamicLoader
		dynamicRes := &admin_v2.ConfigResources{}

		dynamicRes.ClusterConfigs = append(dynamicRes.ClusterConfigs, dynamicLd.ClusterCache.StatusLookup()...)
		dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusLookup()...)
		dynamicRes.RouteConfigs = append(dynamicRes.RouteConfigs, dynamicLd.RouteCache.StatusLookup()...)
		envoy.SetApiVersionInfo(dynamicRes)

		fmt.Fprintln(w, protojson.Format(&admin_v2.ConfigDump{
			DynamicResources: dynamicRes,
		}))
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func httpControllerEnvoy(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	client := controller.GetXdsClient()
	if client == nil {
		fmt.Fprintf(w, "\t%s\n", "invalid bpf.Config.ClientMode")
		return
	}
	dynamicLd := client.AdsStream.Event.DynamicLoader
	dynamicRes := &admin_v2.ConfigResources{}

	dynamicRes.ClusterConfigs = append(dynamicRes.ClusterConfigs, dynamicLd.ClusterCache.StatusRead()...)
	dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusRead()...)
	dynamicRes.RouteConfigs = append(dynamicRes.RouteConfigs, dynamicLd.RouteCache.StatusRead()...)
	envoy.SetApiVersionInfo(dynamicRes)

	fmt.Fprintln(w, protojson.Format(&admin_v2.ConfigDump{
		DynamicResources: dynamicRes,
	}))
}

var cmdServer = newHttpServer()

func StartServer() error {
	go func() {
		// TODO: handle the error
		_ = cmdServer.server.ListenAndServe()
	}()
	return nil
}

func StopServer() error {
	return cmdServer.server.Close()
}
