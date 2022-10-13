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

package nets

// #cgo pkg-config: bpf api-v2-c
// #include "kmesh/include/config.h"
import "C"
import "openeuler.io/mesh/pkg/options"

var config Config

func init() {
	options.Register(&config)
}

type Config struct {
	Protocol   map[string]bool `json:"protocol"`
}

func (c *Config) SetArgs() error {
	return nil
}

func (c *Config) ParseConfig() error {
	c.Protocol = make(map[string]bool)

	c.Protocol["IPV4"]  = C.KMESH_ENABLE_IPV4 == C.KMESH_MODULE_ON
	c.Protocol["IPV6"]  = C.KMESH_ENABLE_IPV6 == C.KMESH_MODULE_ON
	c.Protocol["TCP"]   = C.KMESH_ENABLE_TCP == C.KMESH_MODULE_ON
	c.Protocol["UDP"]   = C.KMESH_ENABLE_UDP == C.KMESH_MODULE_ON
	c.Protocol["HTTP"]  = C.KMESH_ENABLE_HTTP == C.KMESH_MODULE_ON
	c.Protocol["HTTPS"] = C.KMESH_ENABLE_HTTPS == C.KMESH_MODULE_ON

	return nil
}

func (c *Config) IsEnabledProtocol(pro string) bool {
	return c.Protocol[pro]
}

func GetConfig() *Config {
	return &config
}
