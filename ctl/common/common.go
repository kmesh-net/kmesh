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

package common

import (
	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/accesslog"
	"kmesh.net/kmesh/ctl/authz"
	"kmesh.net/kmesh/ctl/dump"
	logcmd "kmesh.net/kmesh/ctl/log"
	"kmesh.net/kmesh/ctl/version"
	"kmesh.net/kmesh/ctl/waypoint"
)

func GetRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "kmeshctl",
		Short:        "Kmesh command line tools to operate and debug Kmesh",
		SilenceUsage: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	rootCmd.AddCommand(logcmd.NewCmd())
	rootCmd.AddCommand(dump.NewCmd())
	rootCmd.AddCommand(waypoint.NewCmd())
	rootCmd.AddCommand(version.NewCmd())
	rootCmd.AddCommand(accesslog.NewCmd())
	rootCmd.AddCommand(authz.NewCmd())

	return rootCmd
}
