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
 */

// Mostly from istio https://github.com/istio/istio/blob/master/cni/pkg/install/kubeconfig.go

// Copyright Istio Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package cni

import (
	"fmt"
	"net"
	"os"

	"k8s.io/client-go/tools/clientcmd/api"
	"k8s.io/client-go/tools/clientcmd/api/latest"
	"sigs.k8s.io/yaml"

	"kmesh.net/kmesh/pkg/utils"
)

const ServiceAccountPath = "/var/run/secrets/kubernetes.io/serviceaccount"

func createKubeConfig() (string, error) {
	k8sServiceHost := os.Getenv("KUBERNETES_SERVICE_HOST")
	if len(k8sServiceHost) == 0 {
		return "", fmt.Errorf("KUBERNETES_SERVICE_HOST not set. Is this not running within a pod?")
	}
	k8sServicePort := os.Getenv("KUBERNETES_SERVICE_PORT")
	if len(k8sServicePort) == 0 {
		return "", fmt.Errorf("KUBERNETES_SERVICE_PORT not set. Is this not running within a pod?")
	}

	cluster := &api.Cluster{
		Server: fmt.Sprintf("https://%s", net.JoinHostPort(k8sServiceHost, k8sServicePort)),
	}

	caFile := ServiceAccountPath + "/ca.crt"
	caContents, err := os.ReadFile(caFile)
	if err != nil {
		return "", err
	}
	cluster.CertificateAuthorityData = caContents

	token, err := os.ReadFile(ServiceAccountPath + "/token")
	if err != nil {
		return "", err
	}

	const contextName = "kmesh-context"
	const clusterName = "local"
	const userName = "kmesh-cni"
	kcfg := &api.Config{
		Kind:        "Config",
		APIVersion:  "v1",
		Preferences: api.Preferences{},
		Clusters: map[string]*api.Cluster{
			clusterName: cluster,
		},
		AuthInfos: map[string]*api.AuthInfo{
			userName: {
				Token: string(token),
			},
		},
		Contexts: map[string]*api.Context{
			contextName: {
				AuthInfo: userName,
				Cluster:  clusterName,
			},
		},
		CurrentContext: contextName,
	}

	lcfg, err := latest.Scheme.ConvertToVersion(kcfg, latest.ExternalVersion)
	if err != nil {
		return "", err
	}
	// Convert to v1 schema which has proper encoding
	fullYaml, err := yaml.Marshal(lcfg)
	if err != nil {
		return "", err
	}

	return string(fullYaml), nil
}

// maybeWriteKubeConfigFile will validate the existing kubeConfig file, and rewrite/replace it if required.
func maybeWriteKubeConfigFile(kubeconfigFilepath string) error {
	kc, err := createKubeConfig()
	if err != nil {
		return err
	}

	if shouldCreateKubeConfigFile(kc, kubeconfigFilepath) {
		log.Info("kubeconfig either does not exist or is out of date, writing a new one")
		if err := utils.AtomicWrite(kubeconfigFilepath, []byte(kc), os.FileMode(0o600)); err != nil {
			return err
		}
		log.Infof("wrote kubeconfig file %s", kubeconfigFilepath)
	}
	return nil
}

// shouldCreateKubeConfigFile returns whether we need to create a kubeconfig file for kmesh-cni.
// or if a kubeconfig exists there, but differs from the current config.
// In any case, an error indicates the file must be (re)written, and no error means no action need be taken
func shouldCreateKubeConfigFile(kubeconfig string, kubeconfigFilepath string) bool {
	existingKC, err := os.ReadFile(kubeconfigFilepath)
	if err != nil {
		log.Debugf("no preexisting kubeconfig at %s, assuming we need to create one", kubeconfigFilepath)
		return true
	}

	if kubeconfig == string(existingKC) {
		log.Debugf("preexisting kubeconfig %s is an exact match for expected, no need to update", kubeconfigFilepath)
		return false
	}

	return true
}
