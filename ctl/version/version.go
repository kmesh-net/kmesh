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
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/version"
)

var log = logger.NewLoggerScope("kmeshctl/version")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Prints out build version info",
		Example: `# Show version of all kmesh components
kmeshctl version

# Show version info of a specific kmesh daemon
kmeshctl version <kmesh-daemon-pod>`,
		Run: func(cmd *cobra.Command, args []string) {
			runVersion(cmd, args)
		},
	}
	return cmd
}

// runVersion output the version info of kmeshctl or kmesh-daemon.
func runVersion(cmd *cobra.Command, args []string) {
	cli, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create kube client: %v", err)
		os.Exit(1)
	}

	if len(args) == 0 {
		v := version.Get()
		if stringMatch(v.GitVersion) {
			cmd.Printf("client version: %s\n", v.GitVersion)
		} else {
			cmd.Printf("client version: %s-%s\n", v.GitVersion, v.GitCommit)
		}

		podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			log.Errorf("failed to get kmesh daemon pods: %v", err)
			os.Exit(1)
		}

		daemonVersions := map[string]int{}
		for _, pod := range podList.Items {
			v, verr := getVersion(cli, pod.Name)
			if verr != nil {
				continue
			}
			if stringMatch(v.GitVersion) {
				daemonVersions[v.GitVersion] = daemonVersions[v.GitVersion] + 1
			} else {
				daemonVersions[v.GitVersion+"-"+v.GitCommit] = daemonVersions[v.GitVersion+"-"+v.GitCommit] + 1
			}
		}
		counts := []string{}
		cmd.Printf("kmesh-daemon version: ")
		for k, v := range daemonVersions {
			counts = append(counts, fmt.Sprintf("%s (%d daemons)", k, v))
		}
		cmd.Printf("%s\n", strings.Join(counts, ", "))
		return
	}

	podName := args[0]
	v, err := getVersion(cli, podName)
	if err != nil {
		os.Exit(1)
	}
	data, merr := json.MarshalIndent(&v, "", "  ")
	if merr != nil {
		log.Errorf("Failed to marshal version info: %v", merr)
		os.Exit(1)
	}
	cmd.Printf("%s\n", string(data))
}

func getVersion(client kube.CLIClient, podName string) (version version.Info, err error) {
	fw, ferr := utils.CreateKmeshPortForwarder(client, podName)
	if ferr != nil {
		log.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, ferr)
		err = ferr
		return
	}
	if serr := fw.Start(); serr != nil {
		log.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, serr)
		err = serr
		return
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s/version", fw.Address())
	resp, herr := http.Get(url)
	if herr != nil {
		log.Errorf("failed to make HTTP request: %v", herr)
		err = herr
		return
	}
	defer resp.Body.Close()

	body, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		log.Errorf("failed to read HTTP response body: %v", rerr)
		err = rerr
		return
	}

	if uerr := json.Unmarshal(body, &version); uerr != nil {
		log.Errorf("failed to unmarshal version info: %v", uerr)
		err = uerr
		return
	}

	return
}

// match release version vx.y.z-(alpha)
func stringMatch(str string) bool {
	pattern := `^v\d+\.\d+\.\d+(-[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*)?$`
	regex := regexp.MustCompile(pattern)

	return regex.MatchString(str)
}