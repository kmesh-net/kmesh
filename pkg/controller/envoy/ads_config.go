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
	configClusterV3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	configCoreV3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extensionsTlsV3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"openeuler.io/mesh/pkg/controller/interfaces"
	"strconv"
	"time"

	configBootstrapV3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	// in order to fix: could not resolve Any message type
	// https://issueexplorer.com/issue/envoyproxy/go-control-plane/450
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"

	"github.com/golang/protobuf/jsonpb"
	"io/ioutil"
	"openeuler.io/mesh/pkg/logger"
	"openeuler.io/mesh/pkg/option"
	"path/filepath"
	"sigs.k8s.io/yaml"
)

const (
	pkgSubsys = "xds"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
	config XdsConfig
)

type XdsConfig struct {
	Path			string
	ServiceNode		string
	ServiceCluster	string
	Ads				*AdsConfig
}

func GetConfig() *XdsConfig {
	return &config
}

func (c *XdsConfig) SetClientArgs() error {
	flag.StringVar(&c.Path, "config-path", "/etc/istio/proxy/envoy-rev0.json", "deploy in kube cluster")
	flag.StringVar(&c.ServiceNode, "service-node", "TODO", "TODO")
	flag.StringVar(&c.ServiceCluster, "service-cluster", "TODO", "TODO")
	return nil
}

func (c *XdsConfig) UnmarshalResources() error {
	var (
		err error
		bootstrap *configBootstrapV3.Bootstrap
	)

	if c.Path, err = filepath.Abs(c.Path); err != nil {
		return err
	}

	if bootstrap, err = loadConfigFile(c.Path); err != nil {
		return err
	}

	if c.Ads, err = NewAdsConfig(bootstrap); err != nil {
		return err
	}

	return nil
}

func (c *XdsConfig) NewClient() (interfaces.ClientFactory, error) {
	return NewAdsClient(c.Ads)
}

func (c *XdsConfig) getNode() *configCoreV3.Node {
	if c.Ads.Node != nil {
		return c.Ads.Node
	}

	return &configCoreV3.Node{
		Id: c.ServiceNode,
		Cluster: c.ServiceCluster,
		Metadata: nil,
	}
}

func loadConfigFile(path string) (*configBootstrapV3.Bootstrap, error) {
	var (
		err       error
		content   []byte
		bootstrap configBootstrapV3.Bootstrap
	)

	if content, err = ioutil.ReadFile(path); err != nil {
		return nil, fmt.Errorf("%s read failed, %s", path, err)
	}

	if option.IsYamlFormat(path) {
		if content, err = yaml.YAMLToJSON(content); err != nil {
			return nil, fmt.Errorf("%s format to json failed, %s", path, err)
		}
	}

	if err = jsonpb.UnmarshalString(string(content), &bootstrap); err != nil {
		return nil, fmt.Errorf("%s unmarshal failed, %s", path, err)
	}

	return &bootstrap, nil
}

type AdsConfig struct {
	Node     *configCoreV3.Node
	APIType  configCoreV3.ApiConfigSource_ApiType
	Clusters []*ClusterConfig
}

type ClusterConfig struct {
	Name           string
	Address        []string
	LbPolicy       configClusterV3.Cluster_LbPolicy
	ConnectTimeout time.Duration
	TlsContext     *extensionsTlsV3.UpstreamTlsContext
}

func NewAdsConfig(bootstrap *configBootstrapV3.Bootstrap) (*AdsConfig, error) {
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

			for _, endpoints := range cluster.GetLoadAssignment().GetEndpoints() {
				for _, lb := range endpoints.GetLbEndpoints() {
					addr := ""

					switch lb.GetEndpoint().GetAddress().GetAddress().(type) {
					case *configCoreV3.Address_Pipe:
						addr = lb.GetEndpoint().GetAddress().GetPipe().GetPath()
					case *configCoreV3.Address_SocketAddress:
						ip := lb.GetEndpoint().GetAddress().GetSocketAddress().GetAddress()
						port := lb.GetEndpoint().GetAddress().GetSocketAddress().GetPortValue()
						addr = ip + ":" + strconv.FormatUint(uint64(port), 10)
					case *configCoreV3.Address_EnvoyInternalAddress:
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
