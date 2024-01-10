/*
 * Copyright 2023 The Kmesh Authors.
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
 *
 * Author: bitcoffee
 * Create: 2023-11-19
 */

package utils

import (
	"os"
	"os/user"
	"path/filepath"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var clientSet *kubernetes.Clientset = nil

func GetK8sclient() (*kubernetes.Clientset, error) {
	var kubeConfig *string
	var home string

	if clientSet != nil {
		return clientSet, nil
	}

	if home = os.Getenv("HOME"); home == "" {
		currentUser, err := user.Current()
		if err != nil {
			log.Errorf("failed to get current user when get k8s config file: %v", err)
			return nil, err
		}
		home = currentUser.HomeDir
	}

	configPath := filepath.Join(home, ".kube", "config")
	kubeConfig = &configPath

	config, err := clientcmd.BuildConfigFromFlags("", *kubeConfig)
	if err != nil {
		log.Errorf("create config error!")
		return nil, err
	}

	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Errorf("create clientset error!")
		return nil, err
	}
	return clientSet, nil
}

// CreateK8sClientSet creates a Kubernetes clientset from a kubeconfig file
func CreateK8sClientSet(kubeconfig string) (*kubernetes.Clientset, error) {
	// Build the client configuration from the kubeconfig file
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, err
	}

	// Create the Kubernetes clientset
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	return clientset, nil
}
