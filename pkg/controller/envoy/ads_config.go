/*
 * Copyright 2023 The Kmesh Authors.
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

 * Author: LemmyHuang
 * Create: 2022-01-08
 */

package envoy

import (
	"flag"
	"strings"

	config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"istio.io/pkg/env"

	// in order to fix: could not resolve Any message type
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3" // nolint

	"kmesh.net/kmesh/pkg/controller/interfaces"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	pkgSubsys  = "xds"
	Decimalism = 10

	// TODO(YaoZengzeng): use appropriate role, "sidecar" or "ztunnel".
	nodeRole                  = "sidecar"
	localHostIPv4             = "127.0.0.1"
	serviceNodeSeparator      = "~"
	defaultClusterLocalDomain = "cluster.local"
)

var (
	log    = logger.NewLoggerField("controller/envoy")
	config XdsConfig
)

type XdsConfig struct {
	ServiceNode      string
	DiscoveryAddress string
	EnableAds        bool
}

func GetConfig() *XdsConfig {
	return &config
}

func (c *XdsConfig) SetClientArgs() error {
	flag.BoolVar(&c.EnableAds, "enable-ads", true, "[if -enable-kmesh] enable control-plane from ads")
	return nil
}

func (c *XdsConfig) Init() error {
	if !c.EnableAds {
		return nil
	}

	podIP := env.Register("INSTANCE_IP", "", "").Get()
	podName := env.Register("POD_NAME", "", "").Get()
	podNamespace := env.Register("POD_NAMESPACE", "", "").Get()
	discoveryAddress := env.Register("MESH_CONTROLLER", "istiod.istio-system.svc:15012", "").Get()

	c.DiscoveryAddress = discoveryAddress

	ip := localHostIPv4
	if podIP != "" {
		ip = podIP
	}

	id := podName + "." + podNamespace
	dnsDomain := podNamespace + ".svc." + defaultClusterLocalDomain

	c.ServiceNode = strings.Join([]string{nodeRole, ip, id, dnsDomain}, serviceNodeSeparator)

	log.Infof("service node %v connect to discovery address %v", c.ServiceNode, c.DiscoveryAddress)

	return nil
}

func (c *XdsConfig) NewClient() (interfaces.ClientFactory, error) {
	return NewAdsClient(c.DiscoveryAddress)
}

func (c *XdsConfig) getNode() *config_core_v3.Node {
	return &config_core_v3.Node{
		Id:       c.ServiceNode,
		Metadata: nil,
	}
}
