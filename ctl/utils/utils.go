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
	"fmt"

	"istio.io/istio/pkg/kube"
)

const (
	KmeshNamespace = "kmesh-system"
	KmeshAdminPort = 15200
)

// Create a new PortForwarder configured for the given Kmesh daemon pod.
func CreateKmeshPortForwarder(podName string) (kube.PortForwarder, error) {
	cli, err := CreateKubeClient()
	if err != nil {
		return nil, err
	}

	fw, err := cli.NewPortForwarder(podName, KmeshNamespace, "", 0, KmeshAdminPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create port forwarder: %v", err)
	}

	return fw, nil
}

func CreateKubeClient() (kube.CLIClient, error) {
	rc, err := kube.DefaultRestConfig("", "")
	if err != nil {
		return nil, fmt.Errorf("failed to get rest.Config for given kube config file and context: %v", err)
	}

	cli, err := kube.NewCLIClient(kube.NewClientConfigForRestConfig(rc))
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %v", err)
	}

	return cli, nil
}
