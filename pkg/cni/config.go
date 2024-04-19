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
 */

package cni

import (
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/options"
)

var config Config

func init() {
	options.Register(&config)
}

type Config struct {
	CniMountNetEtcDIR string
	CniConfigName     string
	CniConfigChained  bool
}

func (c *Config) AttachFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&c.CniMountNetEtcDIR, "cni-etc-path", "/etc/cni/net.d", "cni etc path")
	cmd.PersistentFlags().StringVar(&c.CniConfigName, "conflist-name", "", "cni conflist name")
	cmd.PersistentFlags().BoolVar(&c.CniConfigChained, "plugin-cni-chained", true, "kmesh cni plugins chained to anthor cni")
}

func (c *Config) ParseConfig() error {
	var err error

	if !bpf.GetConfig().AdsEnabled() && !bpf.GetConfig().WdsEnabled() {
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
