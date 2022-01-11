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

package controller

import (
	"flag"
	"fmt"
	"openeuler.io/mesh/pkg/controller/envoy"
	"openeuler.io/mesh/pkg/controller/interfaces"
	"openeuler.io/mesh/pkg/controller/kubernetes"
	"openeuler.io/mesh/pkg/option"
)

const (
	ClientModeKube = "kubernetes"
	ClientModeEnvoy = "envoy"
)

var config Config

func init() {
	option.Register(&config)
}

type Config struct {
	ClientMode	string
	interfaces.ConfigFactory
}

func (c *Config) SetArgs() error {
	var clientModeValue = ClientModeKube
	var clientModeUsage = fmt.Sprintf("controller plane mode: [%s %s]", ClientModeKube, ClientModeEnvoy)

	flag.StringVar(&c.ClientMode, "client-mode", clientModeValue, clientModeUsage)
	if idx := option.FindArgIndex("client-mode"); idx != -1 {
		clientModeValue = option.GetArgValue(idx)
	}

	switch clientModeValue {
	case ClientModeEnvoy:
		c.ConfigFactory = &envoy.XdsConfig{}
	case ClientModeKube:
		c.ConfigFactory = &kubernetes.ApiserverConfig{}
	default:
		return fmt.Errorf("invalid client mode, %s", c.ClientMode)
	}

	return c.ConfigFactory.SetClientArgs()
}

func (c *Config) ParseConfig() error {
	return c.ConfigFactory.UnmarshalResources()
}
