/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2022-03-02
 */

package command

import (
	"fmt"
	"github.com/golang/protobuf/jsonpb"
	"google.golang.org/protobuf/encoding/protojson"
	"io/ioutil"
	"net/http"
	admin_v2 "openeuler.io/mesh/api/v2/admin"
	"openeuler.io/mesh/pkg/controller"
	"openeuler.io/mesh/pkg/controller/envoy"
	"openeuler.io/mesh/pkg/options"
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
	s.mux.HandleFunc(patternBpfSlbMaps, httpBpfSlbMaps)
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
	fmt.Fprintf(w, "\t%s: %s\n", patternBpfSlbMaps,
		"print bpf slb maps in kernel")
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

func httpBpfSlbMaps(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotImplemented)

	fmt.Fprintf(w, "%s: %s\n", patternBpfSlbMaps,
		"TODO")
}

func httpBpfKmeshMaps(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	client := controller.GetAdsClient()
	if client == nil {
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	} else if client.Event == nil {
		fmt.Fprintf(w, "\t%s\n", "none client.Event")
		return
	}

	switch r.Method {
	case http.MethodGet:
		dynamicLd := client.Event.DynamicLoader
		staticLd  := client.Event.StaticLoader
		dynamicRes := &admin_v2.ConfigResources{}
		staticRes  := &admin_v2.ConfigResources{}

		dynamicRes.ClusterConfigs  = append(dynamicRes.ClusterConfigs,  dynamicLd.ClusterCache.StatusLookup()...)
		dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusLookup()...)
		dynamicRes.RouteConfigs    = append(dynamicRes.RouteConfigs,    dynamicLd.RouteCache.StatusLookup()...)
		envoy.SetApiVersionInfo(dynamicRes)

		staticRes.ClusterConfigs  = append(staticRes.ClusterConfigs,  staticLd.ClusterCache.StatusLookup()...)
		staticRes.ListenerConfigs = append(staticRes.ListenerConfigs, staticLd.ListenerCache.StatusLookup()...)
		staticRes.RouteConfigs    = append(staticRes.RouteConfigs,    staticLd.RouteCache.StatusLookup()...)
		envoy.SetApiVersionInfo(staticRes)

		fmt.Fprintln(w, protojson.Format(&admin_v2.ConfigDump{
			StaticResources: staticRes,
			DynamicResources: dynamicRes,
		}))
	case http.MethodPost:
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
	}

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
	staticLd  := client.Event.StaticLoader
	dynamicRes := &admin_v2.ConfigResources{}
	staticRes  := &admin_v2.ConfigResources{}

	dynamicRes.ClusterConfigs  = append(dynamicRes.ClusterConfigs,  dynamicLd.ClusterCache.StatusRead()...)
	dynamicRes.ListenerConfigs = append(dynamicRes.ListenerConfigs, dynamicLd.ListenerCache.StatusRead()...)
	dynamicRes.RouteConfigs    = append(dynamicRes.RouteConfigs,    dynamicLd.RouteCache.StatusRead()...)
	envoy.SetApiVersionInfo(dynamicRes)

	staticRes.ClusterConfigs  = append(staticRes.ClusterConfigs,  staticLd.ClusterCache.StatusRead()...)
	staticRes.ListenerConfigs = append(staticRes.ListenerConfigs, staticLd.ListenerCache.StatusRead()...)
	staticRes.RouteConfigs    = append(staticRes.RouteConfigs,    staticLd.RouteCache.StatusRead()...)
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
