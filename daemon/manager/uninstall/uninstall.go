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

package uninstall

import (
	"flag"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/cni"
)

func NewUninstallCmd() *cobra.Command {
	configs := options.NewBootstrapConfigs()
	cmd := &cobra.Command{
		Use:   "uninstall",
		Short: "Uninstall kmesh-cni",
		Example: `Uninstall kmesh-cni configs before exit:
		kmesh-daemon uninstall`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := configs.ParseConfigs(); err != nil {
				return err
			}
			cniInstaller := cni.NewInstaller(configs.BpfConfig.Mode,
				configs.CniConfig.CniMountNetEtcDIR, configs.CniConfig.CniConfigName, configs.CniConfig.CniConfigChained)
			cniInstaller.Stop()
			return nil
		},
	}

	bindCmdlineFlags(configs, cmd)

	return cmd
}

func bindCmdlineFlags(configs *options.BootstrapConfigs, cmd *cobra.Command) {
	configs.AttachFlags(cmd)
	cmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
}
