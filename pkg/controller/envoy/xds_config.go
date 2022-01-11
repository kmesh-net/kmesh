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
	envoyConfigBootstrapV3 "github.com/envoyproxy/go-control-plane/envoy/config/bootstrap/v3"
	// in order to fix: could not resolve Any message type
	// https://issueexplorer.com/issue/envoyproxy/go-control-plane/450
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	_ "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/golang/protobuf/jsonpb"
	"io/ioutil"
	"openeuler.io/mesh/pkg/controller/interfaces"
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
)

type XdsConfig struct {
	configPath string
	EnvoyConfigBootstrap *envoyConfigBootstrapV3.Bootstrap
}

func (c *XdsConfig) SetClientArgs() error {
	flag.StringVar(&c.configPath, "config-path", "/etc/istio/proxy/envoy-rev0.json", "deploy in kube cluster")
	return nil
}

func (c *XdsConfig) UnmarshalResources() error {
	var err error

	if c.configPath, err = filepath.Abs(c.configPath); err != nil {
		return err
	}

	return c.loadConfigFile()
}

func (c *XdsConfig) NewClient() (interfaces.ClientFactory, error) {
	client := NewXdsClient()
	return client, nil
}

func (c *XdsConfig) loadConfigFile() error {
	var (
		path = c.configPath
		err error
		content []byte
		config envoyConfigBootstrapV3.Bootstrap
	)

	if content, err = ioutil.ReadFile(path); err != nil {
		return fmt.Errorf("%s read failed, %s", path, err)
	}

	if option.IsYamlFormat(path) {
		if content, err = yaml.YAMLToJSON(content); err != nil {
			return fmt.Errorf("%s format to json failed, %s", path, err)
		}
	}

	if err = jsonpb.UnmarshalString(string(content), &config); err != nil {
		return fmt.Errorf("%s unmarshal failed, %s", path, err)
	}

	c.EnvoyConfigBootstrap = &config
	return nil
}
