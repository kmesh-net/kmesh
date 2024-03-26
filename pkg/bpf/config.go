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

package bpf

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"
	"kmesh.net/kmesh/pkg/options"
)

const (
	adsMode      = "ads"
	workloadMode = "workload"
)

var (
	config Config
)

func init() {
	options.Register(&config)
}

type Config struct {
	Mode                string
	BpfFsPath           string
	Cgroup2Path         string
	EnableKmesh         bool
	EnableKmeshWorkload bool
	EnableMda           bool
	BpfVerifyLogSize    int
}

func (c *Config) AttachFlags(cmd *cobra.Command) error {
	cmd.PersistentFlags().StringVar(&c.BpfFsPath, "bpf-fs-path", "/sys/fs/bpf", "bpf fs path")
	cmd.PersistentFlags().StringVar(&c.Cgroup2Path, "cgroup2-path", "/mnt/kmesh_cgroup2", "cgroup2 path")
	cmd.PersistentFlags().StringVar(&c.Mode, "mode", "ads", "controller plane mode, valid values are [ads, workload], by default is ads")
	cmd.PersistentFlags().BoolVar(&c.EnableMda, "enable-mda", false, "enable mda")

	return nil
}

func (c *Config) ParseConfig() error {
	var err error

	c.EnableKmesh = true
	if c.Mode == workloadMode {
		c.EnableKmeshWorkload = true
		c.EnableKmesh = false
	}

	if c.Cgroup2Path, err = filepath.Abs(c.Cgroup2Path); err != nil {
		return err
	}
	if _, err = os.Stat(c.Cgroup2Path); err != nil {
		return err
	}

	if c.BpfFsPath, err = filepath.Abs(c.BpfFsPath); err != nil {
		return err
	}
	if _, err = os.Stat(c.BpfFsPath); err != nil {
		return err
	}

	bpfLogsize := os.Getenv("BPF_LOG_SIZE")
	if bpfLogsize != "" {
		c.BpfVerifyLogSize, err = strconv.Atoi(bpfLogsize)
		if err != nil {
			c.BpfVerifyLogSize = 0
		}
	}

	return nil
}

func GetConfig() *Config {
	return &config
}
