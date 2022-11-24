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
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extensions_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"openeuler.io/mesh/pkg/controller/interfaces"

	config_bootstrap_v3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	// in order to fix: could not resolve Any message type
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"

	"path/filepath"

	"github.com/golang/protobuf/jsonpb"
	"openeuler.io/mesh/pkg/logger"
	"openeuler.io/mesh/pkg/options"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	pkgSubsys  = "xds"
	Decimalism = 10
)

var (
	log    = logger.NewLoggerField("controller/envoy")
	config XdsConfig
)

type XdsConfig struct {
	File           string `json:"-file"`
	ServiceNode    string `json:"-service-node"`
	ServiceCluster string `json:"-service-cluster"`
	EnableAds      bool   `json:"-enable-ads"`
	adsSet         *AdsSet
}

func GetConfig() *XdsConfig {
	return &config
}

func (c *XdsConfig) SetClientArgs() error {
	flag.StringVar(&c.File, "config-file",
		"/etc/kmesh/kmesh.json", "[if -enable-kmesh] deploy in kube cluster")
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

	if content, err = options.LoadConfigFile(c.File); err != nil {
		return err
	}
	if err = jsonpb.UnmarshalString(string(content), &bootstrap); err != nil {
		return err
	}

	if c.adsSet, err = NewAdsConfig(&bootstrap); err != nil {
		return err
	}

	return nil
}

func (c *XdsConfig) NewClient() (interfaces.ClientFactory, error) {
	return NewAdsClient(c.adsSet)
}

func (c *XdsConfig) getNode() *config_core_v3.Node {
	if c.adsSet.Node != nil {
		return c.adsSet.Node
	}

	if c.adsSet.Node != nil {
		return c.adsSet.Node
	} else {
		return &config_core_v3.Node{
			Id:       c.ServiceNode,
			Cluster:  c.ServiceCluster,
			Metadata: nil,
		}
	}
}

type AdsSet struct {
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

func NewAdsConfig(bootstrap *config_bootstrap_v3.Bootstrap) (*AdsSet, error) {
	var (
		err        error
		clusterCfg *ClusterConfig
		meshCtlIp  string
	)

	if bootstrap == nil {
		return nil, fmt.Errorf("bootstrap is nil")
	}
	if err = bootstrap.ValidateAll(); err != nil {
		return nil, err
	}

	ads := &AdsSet{
		Node:    bootstrap.GetNode(),
		APIType: bootstrap.GetDynamicResources().GetAdsConfig().GetApiType(),
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
						meshCtlIp, err = getMeshCtlIp();
						if err != nil {
							log.Infof(err.Error())
						} else if meshCtlIp != "" {
							ip = meshCtlIp
						}
						port := lb.GetEndpoint().GetAddress().GetSocketAddress().GetPortValue()
						addr = ip + ":" + strconv.FormatUint(uint64(port), Decimalism)
					case *config_core_v3.Address_EnvoyInternalAddress:
						// TODO
						log.Infof("envoy internal addr type is unsupport this version")
						continue
					default:
						log.Infof("unsuport addr type, %T", lb.GetEndpoint().GetAddress())
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

func getMeshCtlIp() (meshCtlIp string, err error) {
        var kubeConfig *string

	if home := os.Getenv("HOME"); home != "" {
		configPath := filepath.Join(home, ".kube", "config")
		kubeConfig = &configPath
	} else {
		return meshCtlIp, errors.New("get kube config error!")
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		log.Errorf("create config error!")
		return meshCtlIp, err
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("create clientset error!")
		return meshCtlIp, err
	}

	meshCtl := os.Getenv("MESH_CONTROLLER")
	array := strings.Split(meshCtl, ":")
	if (len(array) != 2) {
		return meshCtlIp, errors.New("get env MESH_CONTROLLER error!")
	}
	ns := array[0]
	name := array[1]
	service, err := clientSet.CoreV1().Services(ns).Get(context.TODO(), name, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get service %s in namespace %s!", name, ns)
		return meshCtlIp, err
	}

	meshCtlIp = service.Spec.ClusterIP
	return meshCtlIp, nil
}
