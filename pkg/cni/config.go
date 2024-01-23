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
 *
 * Author: bitcoffee
 * Create: 2023-11-19
 */

package cni

import (
	"flag"
	"os"
	"path/filepath"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/options"
)

var config Config

func init() {
	options.Register(&config)
}

type Config struct {
	CniMountNetEtcDIR string `json:"-cni-etc-path"`
	CniConfigName     string `json:"-cni-config-name"`
	CniConfigChained  bool   `json:"-cni-config-chained"`
}

func (c *Config) SetArgs() error {
	flag.StringVar(&c.CniMountNetEtcDIR, "cni-etc-path", "/etc/cni/net.d", "cni etc path")
	flag.StringVar(&c.CniConfigName, "conflist-name", "", "cni conflist name")

	flag.BoolVar(&c.CniConfigChained, "plugin-cni-chained", true, "kmesh cni plugins chained to anthor cni")
	return nil
}

func (c *Config) ParseConfig() error {
	var err error

	if !bpf.GetConfig().EnableKmesh {
		return nil
	}

	if c.CniMountNetEtcDIR, err = filepath.Abs(c.CniMountNetEtcDIR); err != nil {
		return err
	}

	if _, err = os.Stat(c.CniMountNetEtcDIR); err != nil {
		return err
	}

	return nil
}

func GetConfig() *Config {
	return &config
}
