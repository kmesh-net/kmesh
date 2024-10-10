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

package dump

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	configDumpPrefix = "/debug/config_dump"
)

var log = logger.NewLoggerScope("kmeshctl/dump")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dump",
		Short: "Dump config of ads or workload mode",
		Example: `# Ads mode:
kmeshctl dump <kmesh-daemon-pod> ads
	  
# Workload mode:
kmeshctl dump <kmesh-daemon-pod> workload`,
		Args: cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			_ = RunDump(cmd, args)
		},
	}
	return cmd
}

func RunDump(cmd *cobra.Command, args []string) error {
	podName := args[0]
	mode := args[1]
	if mode != "ads" && mode != "workload" {
		log.Errorf("Error: Argument must be 'ads' or 'workload'")
		os.Exit(1)
	}

	cli, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}

	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		log.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	if err := fw.Start(); err != nil {
		log.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
	}

	url := fmt.Sprintf("http://%s%s/%s", fw.Address(), configDumpPrefix, mode)
	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("failed to make HTTP request: %v", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Errorf("failed to read HTTP response body: %v", err)
		os.Exit(1)
	}

	fmt.Println(string(body))
	return nil
}
