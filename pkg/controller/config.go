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
	"openeuler.io/mesh/pkg/bpf"
	"openeuler.io/mesh/pkg/controller/envoy"
	"openeuler.io/mesh/pkg/controller/interfaces"
	"openeuler.io/mesh/pkg/controller/kubernetes"
	"openeuler.io/mesh/pkg/options"
)

var config Config

func init() {
	options.Register(&config)
}

type Config struct {
	interfaces.ConfigFactory `json:"controller"`
}

func (c *Config) SetArgs() error {
	kubernetes.GetConfig().SetClientArgs()
	envoy.GetConfig().SetClientArgs()
	return nil
}

func (c *Config) ParseConfig() error {
	if bpf.GetConfig().EnableSlb {
		c.ConfigFactory = kubernetes.GetConfig()
	}
	if bpf.GetConfig().EnableKmesh {
		c.ConfigFactory = envoy.GetConfig()
	}

	return c.ConfigFactory.UnmarshalResources()
}
