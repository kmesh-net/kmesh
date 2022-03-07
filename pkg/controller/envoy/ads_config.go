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
 * Create: 2022-01-08
 */

package envoy

import (
	"flag"
	"fmt"
	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extensions_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"openeuler.io/mesh/pkg/controller/interfaces"
	"strconv"
	"time"

	config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	// in order to fix: could not resolve Any message type
	// https://issueexplorer.com/issue/envoyproxy/go-control-plane/450
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/golang/protobuf/jsonpb"
	"openeuler.io/mesh/pkg/logger"
	"openeuler.io/mesh/pkg/option"
	"path/filepath"
)

const (
	pkgSubsys = "xds"
)

var (
	log = logger.NewLoggerField("controller/envoy")
	config XdsConfig
)

type XdsConfig struct {
	File           string
	ServiceNode    string
	ServiceCluster string
	EnableAds      bool
	Ads            *AdsConfig
}

func GetConfig() *XdsConfig {
	return &config
}

func (c *XdsConfig) SetClientArgs() error {
	flag.StringVar(&c.File, "config-file", "/etc/istio/proxy/envoy-rev0.json", "[if -enable-kmesh] deploy in kube cluster")
	flag.StringVar(&c.ServiceNode, "service-node", "TODO", "[if -enable-kmesh] TODO")
	flag.StringVar(&c.ServiceCluster, "service-cluster", "TODO", "[if -enable-kmesh] TODO")
	flag.BoolVar(&c.EnableAds, "enable-ads", true, "[if -enable-kmesh] enable control-plane from ads")
	return nil
}

func (c *XdsConfig) UnmarshalResources() error {
	var (
		err       error
		content   []byte
		bootstrap config_bootstrap_v3.Bootstrap
	)

	if !c.EnableAds {
		return nil
	}

	if c.File, err = filepath.Abs(c.File); err != nil {
		return err
	}

	if content, err = option.LoadConfigFile(c.File); err != nil {
		return err
	}
	if err = jsonpb.UnmarshalString(string(content), &bootstrap); err != nil {
		return err
	}

	if c.Ads, err = NewAdsConfig(&bootstrap); err != nil {
		return err
	}

	return nil
}

func (c *XdsConfig) NewClient() (interfaces.ClientFactory, error) {
	return NewAdsClient(c.Ads)
}

func (c *XdsConfig) getNode() *config_core_v3.Node {
	if c.Ads.Node != nil {
		return c.Ads.Node
	}

	if c.Ads.Node != nil {
		return c.Ads.Node
	} else {
		return &config_core_v3.Node{
			Id: c.ServiceNode,
			Cluster: c.ServiceCluster,
			Metadata: nil,
		}
	}
}

type AdsConfig struct {
	Node     *config_core_v3.Node
	APIType  config_core_v3.ApiConfigSource_ApiType
	Clusters []*ClusterConfig
}

type ClusterConfig struct {
	Name           string
	Address        []string
	LbPolicy       config_cluster_v3.Cluster_LbPolicy
	ConnectTimeout time.Duration
	TlsContext     *extensions_tls_v3.UpstreamTlsContext
}

func NewAdsConfig(bootstrap *config_bootstrap_v3.Bootstrap) (*AdsConfig, error) {
	var (
		err error
		clusterCfg *ClusterConfig
	)

	if bootstrap == nil {
		return nil, fmt.Errorf("bootstrap is nil")
	}
	if err = bootstrap.ValidateAll(); err != nil {
		return nil, err
	}

	ads := &AdsConfig{
		Node:         bootstrap.GetNode(),
		APIType:      bootstrap.GetDynamicResources().GetAdsConfig().GetApiType(),
	}

	for _, svc := range bootstrap.GetDynamicResources().GetAdsConfig().GetGrpcServices() {
		name := svc.GetEnvoyGrpc().GetClusterName()
		for _, cluster := range bootstrap.GetStaticResources().GetClusters() {
			if name != cluster.GetName() {
				continue
			}

			clusterCfg = new(ClusterConfig)
			clusterCfg.Name = name
			clusterCfg.LbPolicy = cluster.GetLbPolicy()
			clusterCfg.ConnectTimeout = cluster.GetConnectTimeout().AsDuration()

			for _, localityLb := range cluster.GetLoadAssignment().GetEndpoints() {
				for _, lb := range localityLb.GetLbEndpoints() {
					addr := ""

					switch lb.GetEndpoint().GetAddress().GetAddress().(type) {
					case *config_core_v3.Address_Pipe:
						addr = lb.GetEndpoint().GetAddress().GetPipe().GetPath()
					case *config_core_v3.Address_SocketAddress:
						ip := lb.GetEndpoint().GetAddress().GetSocketAddress().GetAddress()
						port := lb.GetEndpoint().GetAddress().GetSocketAddress().GetPortValue()
						addr = ip + ":" + strconv.FormatUint(uint64(port), 10)
					case *config_core_v3.Address_EnvoyInternalAddress:
						// TODO
						continue
					}

					clusterCfg.Address = append(clusterCfg.Address, addr)
				}
			}

			ads.Clusters = append(ads.Clusters, clusterCfg)
		}
	}

	return ads, nil
}
