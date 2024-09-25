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

package main

import (
	"os"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/dump"
	logcmd "kmesh.net/kmesh/ctl/log"
)

func main() {
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

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
