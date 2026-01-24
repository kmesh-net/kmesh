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
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/pkg/constants"
)

type BpfConfig struct {
	Mode                 string
	BpfFsPath            string
	Cgroup2Path          string
	EnableMda            bool
	EnableMonitoring     bool
	EnablePeriodicReport bool
	EnableProfiling      bool
	EnableIPsec          bool
	EnableDNSProxy       bool
}

func (c *BpfConfig) AttachFlags(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&c.BpfFsPath, "bpf-fs-path", "/sys/fs/bpf", "bpf fs path")
	cmd.PersistentFlags().StringVar(&c.Cgroup2Path, "cgroup2-path", "/mnt/kmesh_cgroup2", "cgroup2 path")
	cmd.PersistentFlags().StringVar(&c.Mode, "mode", "dual-engine", "controller plane mode, valid values are [kernel-native, dual-engine]")
	cmd.PersistentFlags().BoolVar(&c.EnableMda, "enable-mda", false, "enable mda")
	cmd.PersistentFlags().BoolVar(&c.EnableMonitoring, "monitoring", true, "enable kmesh traffic monitoring in daemon process")
	cmd.PersistentFlags().BoolVar(&c.EnablePeriodicReport, "periodic-report", false, "enable kmesh periodic report in daemon process")
	cmd.PersistentFlags().BoolVar(&c.EnableProfiling, "profiling", false, "whether to enable profiling or not, default to false")
	cmd.PersistentFlags().BoolVar(&c.EnableIPsec, "enable-ipsec", false, "enable ipsec encryption and authentication between nodes")
	cmd.PersistentFlags().BoolVar(&c.EnableDNSProxy, "enable-dns-proxy", false, "enable dns proxy in dual-engine mode, will start a dns server in kmesh daemon to serve dns requests")
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

	return nil
}

func (c *BpfConfig) KernelNativeEnabled() bool {
	return c.Mode == constants.KernelNativeMode
}

func (c *BpfConfig) DualEngineEnabled() bool {
	return c.Mode == constants.DualEngineMode
}
