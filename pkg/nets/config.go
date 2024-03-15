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

package nets

// #cgo pkg-config: bpf api-v2-c
// #include "kmesh/include/config.h"
import "C"
import "kmesh.net/kmesh/pkg/options"

var config Config
var protocol = map[string]bool{
	"IPV4":  C.KMESH_ENABLE_IPV4 == C.KMESH_MODULE_ON,
	"IPV6":  C.KMESH_ENABLE_IPV6 == C.KMESH_MODULE_ON,
	"TCP":   C.KMESH_ENABLE_TCP == C.KMESH_MODULE_ON,
	"UDP":   C.KMESH_ENABLE_UDP == C.KMESH_MODULE_ON,
	"HTTP":  C.KMESH_ENABLE_HTTP == C.KMESH_MODULE_ON,
	"HTTPS": C.KMESH_ENABLE_HTTPS == C.KMESH_MODULE_ON,
}

func init() {
	options.Register(&config)
}

// Config nets configs
type Config struct {
	Protocol map[string]bool `json:"protocol"`
}

// SetArgs not implemented
func (c *Config) SetArgs() error {
	return nil
}

// ParseConfig parses the config of nets
func (c *Config) ParseConfig() error {
	c.Protocol = make(map[string]bool)
	c.Protocol = protocol
	return nil
}

// IsEnabledProtocol returns true if the protocol is supported
func (c *Config) IsEnabledProtocol(pro string) bool {
	return protocol[pro]
}

// GetConfig function to get config
func GetConfig() *Config {
	return &config
}
