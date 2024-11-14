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

package kube

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// CreateKubeClient creates a kube client with the given kubeconfig file, if no kubeconfig specified, in cluster kubeconfig will be used.
// applyFuncs is optional, which can be used to tune client rest.Config
func CreateKubeClient(kubeConfig string, applyFuncs ...func(c *rest.Config)) (kubernetes.Interface, error) {
	var restConfig *rest.Config
	var err error

	if kubeConfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", kubeConfig)
	} else {
		restConfig, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	for _, fn := range applyFuncs {
		fn(restConfig)
	}
	restConfig.Proxy

	return kubernetes.NewForConfig(restConfig)
}
