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
 * Create: 2022-03-03
 */

package command

import (
	"flag"
	"path/filepath"
	"time"

	"openmesh.io/mesh/pkg/options"
)

const (
	adminAddr   = "localhost:15200"
	adminUrl    = "http://" + adminAddr
	contentType = "application/json"

	patternHelp                 = "/help"
	patternOptions              = "/options"
	patternBpfKmeshMaps         = "/bpf/kmesh/maps"
	patternControllerEnvoy      = "/controller/envoy"
	patternControllerKubernetes = "/controller/kubernetes"

	httpTimeout = time.Second * 20
)

var config Config

type Config struct {
	File            string
	ConfigResources []byte
}

func (c *Config) SetArgs() error {
	flag.StringVar(&c.File, "config-file", "./config-resources.json", "input config-resources to bpf maps")
	return nil
}

func (c *Config) ParseConfig() error {
	var (
		err     error
		content []byte
	)

	if c.File, err = filepath.Abs(c.File); err != nil {
		return err
	}

	if content, err = options.LoadConfigFile(c.File); err != nil {
		return err
	}

	c.ConfigResources = content
	return nil
}
