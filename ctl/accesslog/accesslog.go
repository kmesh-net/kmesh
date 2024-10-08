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

package accesslog

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"istio.io/istio/pkg/kube"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/logger"
)

const (
	patternAccesslog = "/accesslog"
)

var log = logger.NewLoggerScope("kmeshctl/accesslog")

func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "accesslog",
		Short: "Enable or disable Kmesh's accesslog",
		Example: `# Enable Kmesh's accesslog:
kmeshctl accesslog <kmesh-daemon-pod> enable

# Disable Kmesh's accesslog:
kmeshctl accesslog <kmesh-daemon-pod> disable`,
		Args: cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			SetAccesslog(cmd, args)
		},
	}
	return cmd
}

func SetAccesslog(cmd *cobra.Command, args []string) {
	var info string
	accesslogFlag := args[len(args)-1]
	if accesslogFlag == "enable" {
		info = "true"
	} else if accesslogFlag == "disable" {
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
			SetAccesslogPerKmeshDaemon(cli, pod.GetName(), info)
		}
	} else {
		// Processes accesslog triggers for specified kmesh daemon.
		for _, podname := range args[:len(args)-1] {
			SetAccesslogPerKmeshDaemon(cli, podname, info)
		}
	}
}

func SetAccesslogPerKmeshDaemon(cli kube.CLIClient, podName, info string) {
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

	url := fmt.Sprintf("http://%s%s?enable=%s", fw.Address(), patternAccesslog, info)

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
