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

package dump

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/pkg/status"
)

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump config of ads or workload mode",
		Example: `Ads mode:
		kmesh-daemon dump ads
	  
	  Workload mode:
		kmesh-daemon dump workload`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			_ = RunDump(cmd, args)
		},
	}
	return cmd
}

func RunDump(cmd *cobra.Command, args []string) error {
	mode := args[0]
	if mode != "ads" && mode != "workload" {
		fmt.Println("Error: Argument must be 'ads' or 'workload'")
		os.Exit(1)
	} else {
		url := status.GetConfigDumpAddr(mode)
		resp, err := http.Get(url)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("Error reading response: %v\n", err)
			os.Exit(1)
		}

		fmt.Println(string(body))
	}
	return nil
}
