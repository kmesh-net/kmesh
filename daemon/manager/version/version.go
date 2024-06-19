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

package version

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/pkg/version"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version of kmesh daemon",
		Run: func(cmd *cobra.Command, args []string) {
			_ = RunVersion(cmd)
		},
	}
	return cmd
}

// RunVersion provides the version information of kmesh daemon in format depending on arguments
// specified in cobra.Command.
func RunVersion(cmd *cobra.Command) error {
	v := version.Get()

	y, err := json.MarshalIndent(&v, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(y))

	return nil
}
