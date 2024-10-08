/*
 * Copyright The Kmesh Authors.
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
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/pkg/constants"
)

type BpfConfig struct {
	Mode            string
	BpfFsPath       string
	Cgroup2Path     string
	EnableMda       bool
	EnableBpfLog    bool
	EnableAccesslog bool
}

func (c *BpfConfig) AttachFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&c.BpfFsPath, "bpf-fs-path", "/sys/fs/bpf", "bpf fs path")
	cmd.PersistentFlags().StringVar(&c.Cgroup2Path, "cgroup2-path", "/mnt/kmesh_cgroup2", "cgroup2 path")
	cmd.PersistentFlags().StringVar(&c.Mode, "mode", "workload", "controller plane mode, valid values are [ads, workload]")
	cmd.PersistentFlags().BoolVar(&c.EnableMda, "enable-mda", false, "enable mda")
	cmd.PersistentFlags().BoolVar(&c.EnableBpfLog, "enable-bpf-log", false, "enable ebpf log in daemon process")
	cmd.PersistentFlags().BoolVar(&c.EnableAccesslog, "enable-accesslog", false, "enable accesslog in daemon process")
}

func (c *BpfConfig) ParseConfig() error {
	var err error

	if c.Mode != constants.AdsMode && c.Mode != constants.WorkloadMode {
		return fmt.Errorf("invalid mode value, should be `ads` or `workload`")
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

	return nil
}

func (c *BpfConfig) AdsEnabled() bool {
	return c.Mode == constants.AdsMode
}

func (c *BpfConfig) WdsEnabled() bool {
	return c.Mode == constants.WorkloadMode
}
