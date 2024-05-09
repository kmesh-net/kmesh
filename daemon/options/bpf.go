/*
 * Copyright 2024 The Kmesh Authors.
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

package options

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/pkg/constants"
)

type BpfConfig struct {
	Mode             string
	BpfFsPath        string
	Cgroup2Path      string
	EnableMda        bool
	BpfVerifyLogSize int
}

func (c *BpfConfig) AttachFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&c.BpfFsPath, "bpf-fs-path", "/sys/fs/bpf", "bpf fs path")
	cmd.PersistentFlags().StringVar(&c.Cgroup2Path, "cgroup2-path", "/mnt/kmesh_cgroup2", "cgroup2 path")
	cmd.PersistentFlags().StringVar(&c.Mode, "mode", "workload", "controller plane mode, valid values are [ads, workload]")
	cmd.PersistentFlags().BoolVar(&c.EnableMda, "enable-mda", false, "enable mda")
}

func (c *BpfConfig) ParseConfig() error {
	var err error

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

func (c *BpfConfig) AdsEnabled() bool {
	return c.Mode == constants.AdsMode
}

func (c *BpfConfig) WdsEnabled() bool {
	return c.Mode == constants.WorkloadMode
}
