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
 * Create: 2022-03-03
 */

package command

import (
	"flag"
	"openeuler.io/mesh/pkg/options"
	"path/filepath"
	"time"
)

const (
	adminAddr      = "localhost:15200"
	adminUrl       = "http://" + adminAddr
	contentType    = "application/json"

	patternHelp                 = "/help"
	patternOptions              = "/options"
	patternBpfSlbMaps           = "/bpf/slb/maps"
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
		err        error
		content    []byte
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
