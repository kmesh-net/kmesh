/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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

 * Author: LemmyHuang
 * Create: 2022-03-02
 */

package command

import (
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/golang/protobuf/jsonpb"
	"google.golang.org/protobuf/encoding/protojson"

	admin_v2 "oncn.io/mesh/api/v2/admin"
	"oncn.io/mesh/pkg/controller"
	"oncn.io/mesh/pkg/controller/envoy"
	"oncn.io/mesh/pkg/options"
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
	s.mux.HandleFunc(patternControllerKubernetes, httpControllerKubernetes)

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
	fmt.Fprintf(w, "\t%s: %s\n", patternControllerKubernetes,
		"print control-plane in kubernetes cache")
}

func httpOptions(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, options.String())
}

func httpBpfKmeshMaps(w http.ResponseWriter, r *http.Request) {
	client := controller.GetAdsClient()
	if client == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	} else if client.Event == nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "\t%s\n", "none client.Event")
		return
	}

	switch r.Method {
	case http.MethodGet:
		dynamicLd := client.Event.DynamicLoader
		staticLd := client.Event.StaticLoader
		dynamicRes := &admin_v2.ConfigResources{}
		staticRes := &admin_v2.ConfigResources{}

		dynamicRes.ClusterConfigs = append(dynamicRes.ClusterConfigs, dynamicLd.ClusterCache.StatusLookup()...)
		dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusLookup()...)
		dynamicRes.RouteConfigs = append(dynamicRes.RouteConfigs, dynamicLd.RouteCache.StatusLookup()...)
		envoy.SetApiVersionInfo(dynamicRes)

		staticRes.ClusterConfigs = append(staticRes.ClusterConfigs, staticLd.ClusterCache.StatusLookup()...)
		staticRes.ListenerConfigs = append(staticRes.ListenerConfigs, staticLd.ListenerCache.StatusLookup()...)
		staticRes.RouteConfigs = append(staticRes.RouteConfigs, staticLd.RouteCache.StatusLookup()...)
		envoy.SetApiVersionInfo(staticRes)

		fmt.Fprintln(w, protojson.Format(&admin_v2.ConfigDump{
			StaticResources:  staticRes,
			DynamicResources: dynamicRes,
		}))
	case http.MethodPost:
		if controller.IsAdsEnable() {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "This operation is not supported, because kmesh starts with -enable-ads=true.")
			return
		}
		dump := &admin_v2.ConfigDump{}
		content, err := ioutil.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "body read failed")
			return
		}
		if err = jsonpb.UnmarshalString(string(content), dump); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w, "body unmarshal failed")
			return
		}

		client.Event.NewAdminRequest(dump.GetStaticResources())
	default:
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusOK)
	return
}

func httpControllerEnvoy(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	client := controller.GetAdsClient()
	if client == nil {
		fmt.Fprintf(w, "\t%s\n", "invalid bpf.Config.ClientMode")
		return
	}
	dynamicLd := client.Event.DynamicLoader
	staticLd := client.Event.StaticLoader
	dynamicRes := &admin_v2.ConfigResources{}
	staticRes := &admin_v2.ConfigResources{}

	dynamicRes.ClusterConfigs = append(dynamicRes.ClusterConfigs, dynamicLd.ClusterCache.StatusRead()...)
	dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusRead()...)
	dynamicRes.RouteConfigs = append(dynamicRes.RouteConfigs, dynamicLd.RouteCache.StatusRead()...)
	envoy.SetApiVersionInfo(dynamicRes)

	staticRes.ClusterConfigs = append(staticRes.ClusterConfigs, staticLd.ClusterCache.StatusRead()...)
	staticRes.ListenerConfigs = append(staticRes.ListenerConfigs, staticLd.ListenerCache.StatusRead()...)
	staticRes.RouteConfigs = append(staticRes.RouteConfigs, staticLd.RouteCache.StatusRead()...)
	envoy.SetApiVersionInfo(staticRes)

	fmt.Fprintln(w, protojson.Format(&admin_v2.ConfigDump{
		StaticResources:  staticRes,
		DynamicResources: dynamicRes,
	}))
}

func httpControllerKubernetes(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)

	fmt.Fprintf(w, "%s: %s\n", patternControllerKubernetes,
		"TODO")
}

var cmdServer = newHttpServer()

func StartServer() error {
	go cmdServer.server.ListenAndServe()
	return nil
}

func StopServer() error {
	return cmdServer.server.Close()
}
