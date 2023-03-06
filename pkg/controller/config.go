/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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

package controller

import (
	"openeuler.io/mesh/pkg/bpf"
	"openeuler.io/mesh/pkg/controller/envoy"
	"openeuler.io/mesh/pkg/controller/interfaces"
	"openeuler.io/mesh/pkg/options"
)

var config Config

func init() {
	options.Register(&config)
}

type Config struct {
	interfaces.ConfigFactory `json:"controller"`
}

// SetArgs set controller command arguments
func (c *Config) SetArgs() error {
	envoy.GetConfig().SetClientArgs()
	return nil
}

func (c *Config) ParseConfig() error {
	if bpf.GetConfig().EnableKmesh {
		c.ConfigFactory = envoy.GetConfig()
	}

	return c.ConfigFactory.UnmarshalResources()
}
