/*
 * Copyright The Kmesh Authors.
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

package config

import (
	"encoding/json"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"
	"istio.io/istio/pkg/cluster"
	"istio.io/istio/pkg/model"
	"istio.io/istio/pkg/util/protomarshal"
	"istio.io/pkg/env"

	// in order to fix: could not resolve Any message type
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	sidecarNodeRole           = "sidecar"
	ztunnelNodeRole           = "ztunnel"
	localHostIPv4             = "127.0.0.1"
	serviceNodeSeparator      = "~"
	defaultClusterLocalDomain = "cluster.local"
)

var (
	log    = logger.NewLoggerScope("controller/config")
	config *XdsConfig
)

type XdsConfig struct {
	ServiceNode      string
	DiscoveryAddress string
	Metadata         *model.BootstrapNodeMetadata
	Node             *corev3.Node
}

func NewXDSConfig(mode string) *XdsConfig {
	c := &XdsConfig{
		Metadata: &model.BootstrapNodeMetadata{},
	}
	podIP := env.Register("INSTANCE_IP", "", "").Get()
	podName := env.Register("POD_NAME", "", "").Get()
	podNamespace := env.Register("POD_NAMESPACE", "", "").Get()
	c.DiscoveryAddress = env.Register("XDS_ADDRESS", "istiod.istio-system.svc:15012", "").Get()
	clusterID := env.Register("CLUSTER_ID", "Kubernetes", "").Get()
	sa := env.Register("SERVICE_ACCOUNT", "", "").Get()
	nodeName := env.Register("NODE_NAME", "", "").Get()
	meshID := env.Register("MESH_ID", "cluster.local", "").Get()

	// TODO: fix it once we want to support VM application
	ip := localHostIPv4
	if podIP != "" {
		ip = podIP
	}
	id := podName + "." + podNamespace
	dnsDomain := podNamespace + ".svc." + defaultClusterLocalDomain

	c.ServiceNode = strings.Join([]string{getNodeRole(mode), ip, id, dnsDomain}, serviceNodeSeparator)

	log.Infof("proxy %v connect to discovery address %v", c.ServiceNode, c.DiscoveryAddress)

	c.Metadata.Namespace = podNamespace
	c.Metadata.ClusterID = cluster.ID(clusterID)
	c.Metadata.InstanceIPs = []string{ip}
	// TODO: add labels to support localiy load balancing
	c.Metadata.Labels = nil
	c.Metadata.MeshID = meshID
	c.Metadata.NodeName = nodeName
	c.Metadata.NodeMetadata.ServiceAccount = sa

	return c
}

func GetConfig(mode string) *XdsConfig {
	if config != nil {
		return config
	}
	config = NewXDSConfig(mode)
	return config
}

func (c *XdsConfig) GetNode() *corev3.Node {
	if c.Node != nil {
		return c.Node
	}

	nodeMetadata, err := nodeMetadataToStruct(c.Metadata)
	if err != nil {
		log.Fatalf("failed to convert node metadata to struct, %v", err)
	}
	c.Node = &corev3.Node{
		Id:       c.ServiceNode,
		Metadata: nodeMetadata,
	}
	return c.Node
}

func nodeMetadataToStruct(meta *model.BootstrapNodeMetadata) (*structpb.Struct, error) {
	b, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	pbs := &structpb.Struct{}
	if err := protomarshal.Unmarshal(b, pbs); err != nil {
		return nil, err
	}
	return pbs, nil
}

func getNodeRole(mode string) string {
	switch mode {
	case constants.DualEngineMode:
		return ztunnelNodeRole
	default:
		return sidecarNodeRole
	}
}
