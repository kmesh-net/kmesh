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

package utils

import (
	"context"
	"fmt"
	"sort"

	"kmesh.net/kmesh/pkg/kube"
)

const (
	KmeshNamespace = "kmesh-system"
	KmeshLabel     = "app=kmesh"
	KmeshAdminPort = 15200
)

func CreateKubeClient() (kube.CLIClient, error) {
	cli, err := kube.NewCLIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %v", err)
	}

	return cli, nil
}

// CreateKmeshPortForwarder Create a new PortForwarder configured for the given Kmesh daemon pod.
func CreateKmeshPortForwarder(cliClient kube.CLIClient, podName string) (kube.PortForwarder, error) {
	fw, err := cliClient.NewPortForwarder(podName, KmeshNamespace, "", 0, KmeshAdminPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create port forwarder: %v", err)
	}

	return fw, nil
}

// GetKmeshDaemonPods returns a list of Kmesh daemon pod names.
func GetKmeshDaemonPods(ctx context.Context, cli kube.CLIClient) ([]string, error) {
	podList, err := cli.PodsForSelector(ctx, KmeshNamespace, KmeshLabel)
	if err != nil {
		return nil, err
	}
	if podList == nil {
		return nil, nil
	}
	var podNames []string
	for _, pod := range podList.Items {
		podNames = append(podNames, pod.GetName())
	}
	sort.Strings(podNames)
	return podNames, nil
}
