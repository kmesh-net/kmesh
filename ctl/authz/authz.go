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

package authz

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	patternAuthz = "/authz"
)

var log = logger.NewLoggerScope("kmeshctl/authz")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "authz",
		Short: "Enable or disable xdp authz eBPF Prog for Kmesh's authz offloading",
		Example: `# Enable/Disable Kmesh's authz offloading in the specified kmesh daemon:
 kmeshctl authz <kmesh-daemon-pod> enable/disable
 
 # If you want to enable or disable authz offloading of all Kmeshs in the cluster
 kmeshctl authz enable/disable`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			SetAuthz(cmd, args)
		},
	}
	return cmd
}

func SetAuthz(cmd *cobra.Command, args []string) {
	var info string
	authzFlag := args[len(args)-1]
	if authzFlag == "enable" {
		info = "true"
	} else if authzFlag == "disable" {
		info = "false"
	} else {
		log.Errorf("Error: Argument must be 'enable' or 'disable'")
		os.Exit(1)
	}

	cli, err := utils.CreateKubeClient()
	if err != nil {
		log.Errorf("failed to create cli client: %v", err)
		os.Exit(1)
	}

	if len(args) == 1 {
		// Perform operations on all kmesh daemons.
		podList, err := cli.PodsForSelector(context.TODO(), utils.KmeshNamespace, utils.KmeshLabel)
		if err != nil {
			log.Errorf("failed to get kmesh podList: %v", err)
			os.Exit(1)
		}
		for _, pod := range podList.Items {
			SetAuthzPerKmeshDaemon(cli, pod.GetName(), info)
		}
	} else {
		// Processes authz triggers for specified kmesh daemon.
		for _, podname := range args[:len(args)-1] {
			SetAuthzPerKmeshDaemon(cli, podname, info)
		}
	}
}

func SetAuthzPerKmeshDaemon(cli kube.CLIClient, podName, info string) {
	fw, err := utils.CreateKmeshPortForwarder(cli, podName)
	if err != nil {
		log.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	if err := fw.Start(); err != nil {
		log.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %v", podName, err)
		os.Exit(1)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternAuthz, info)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		log.Errorf("Error creating request: %v", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Errorf("failed to make HTTP request: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Errorf("Error: received status code %d", resp.StatusCode)
		return
	}
}
