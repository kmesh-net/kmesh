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

package version

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var log = logger.NewLoggerScope("kmeshctl/version")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Prints out build version info",
		Example: `# Show version of kmeshctl
kmeshctl version

# Show version info of a specific Kmesh daemon
kmeshctl version <kmesh-daemon-pod>`,
		Run: func(cmd *cobra.Command, args []string) {
			_ = RunVersion(cmd, args)
		},
	}
	return cmd
}

// RunVersion provides the version info of kmeshctl or specific Kmesh daemon.
func RunVersion(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		v := version.Get()
		cmd.Printf("%s\n", v.GitVersion)

		return nil
	}

	podName := args[0]

	fw, err := utils.CreateKmeshPortForwarder(podName)
	if err != nil {
		log.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	if err := fw.Start(); err != nil {
		log.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s/version", fw.Address())
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

	cmd.Println(string(body))

	return nil
}
