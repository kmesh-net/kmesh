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
	"google.golang.org/protobuf/encoding/protojson"
	"net/http"
	admin_v2 "openeuler.io/mesh/api/v2/admin"
	"openeuler.io/mesh/pkg/controller"
	"time"
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
		Addr: "localhost:15200",
		Handler: s.mux,
		ReadTimeout: time.Second * 3,
		WriteTimeout: time.Second * 3,
	}

	s.mux.HandleFunc("/help", httpHelp)
	s.mux.HandleFunc("/options", httpOptions)
	s.mux.HandleFunc("/bpf/maps", httpBpfMaps)
	s.mux.HandleFunc("/controller/envoy", httpControllerEnvoy)
	s.mux.HandleFunc("/controller/kubernetes", httpControllerKubernetes)

	return s
}

func httpHelp(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "\t%s: %s\n", "/help",
		"print list of commands")
	fmt.Fprintf(w, "\t%s: %s\n", "/options",
		"print config options")
	fmt.Fprintf(w, "\t%s: %s\n", "/bpf/maps",
		"print bpf maps in kernel")
	fmt.Fprintf(w, "\t%s: %s\n", "/controller/envoy",
		"print control-plane in envoy cache")
	fmt.Fprintf(w, "\t%s: %s\n", "/controller/kubernetes",
		"print control-plane in kubernetes cache")
}

func httpOptions(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s: %s\n", "/options",
		"TODO")
}

func httpBpfMaps(w http.ResponseWriter, r *http.Request) {
	client := controller.GetAdsClient()
	if client == nil {
		fmt.Fprintf(w, "\t%s\n", "invalid ClientMode")
		return
	}
	loader := client.GetEventLoader()
	dump := &admin_v2.ConfigDump{}

	dump.ClusterConfigs = append(dump.ClusterConfigs, loader.ClusterCache.StatusLookup()...)
	dump.RouteConfigs = append(dump.RouteConfigs, loader.RouteCache.StatusLookup()...)
	dump.ListenerConfigs = append(dump.ListenerConfigs, loader.ListenerCache.StatusLookup()...)

	w.Write([]byte(protojson.Format(dump)))
}

func httpControllerEnvoy(w http.ResponseWriter, r *http.Request) {
	client := controller.GetAdsClient()
	if client == nil {
		fmt.Fprintf(w, "\t%s\n", "invalid bpf.Config.ClientMode")
		return
	}
	loader := client.GetEventLoader()
	dump := &admin_v2.ConfigDump{}

	for _, cluster := range loader.ClusterCache {
		dump.ClusterConfigs = append(dump.ClusterConfigs, cluster)
	}
	for _, route := range loader.RouteCache {
		dump.RouteConfigs = append(dump.RouteConfigs, route)
	}
	for _, listener := range loader.ListenerCache {
		dump.ListenerConfigs = append(dump.ListenerConfigs, listener)
	}

	w.Write([]byte(protojson.Format(dump)))
}

func httpControllerKubernetes(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "%s: %s\n", "/controller/kubernetes",
		"TODO")
}

var cmdServer *httpServer = newHttpServer()

func StartServer() error {
	return cmdServer.server.ListenAndServe()
}

func StopServer() error {
	return cmdServer.server.Close()
}
