/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2022-01-08
 */

package kubernetes

import (
	"flag"
	"fmt"
	"k8s.io/client-go/kubernetes"
	client_rest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"openeuler.io/mesh/pkg/controller/interfaces"
	"openeuler.io/mesh/pkg/logger"
	"path/filepath"
	"time"
)

const (
	pkgSubsys = "apiserver"
	DefaultRefreshDelay = time.Second * 3
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
	config ApiserverConfig
)

type ApiserverConfig struct {
	EnableInCluster bool
	RefreshDelay    time.Duration
	ClientSet       kubernetes.Interface
}

func GetConfig() *ApiserverConfig {
	return &config
}

func (c *ApiserverConfig) SetClientArgs() error {
	flag.BoolVar(&c.EnableInCluster, "enable-in-cluster", false, "[if -enable-slb] deploy in kube cluster by DaemonSet")
	return nil
}

func (c *ApiserverConfig) UnmarshalResources() error {
	var (
		err error
		rest *client_rest.Config
	)

	if c.EnableInCluster {
		rest, err = client_rest.InClusterConfig()
		if err != nil {
			return fmt.Errorf("kube build config in cluster failed, %s", err)
		}
	} else {
		home := homedir.HomeDir()
		if home == "" {
			return fmt.Errorf("kube get homedir failed")
		}
		cfgPath := filepath.Join(home, ".kube", "config")
		rest, err = clientcmd.BuildConfigFromFlags("", cfgPath)
		if err != nil {
			return fmt.Errorf("kube build config failed, %s", err)
		}
	}

	c.ClientSet, err = kubernetes.NewForConfig(rest)
	if err != nil {
		return fmt.Errorf("kube new clientset failed, %s", err)
	}

	c.RefreshDelay = DefaultRefreshDelay
	return nil
}

func (c *ApiserverConfig) NewClient() (interfaces.ClientFactory, error) {
	return NewApiserverClient(c.ClientSet)
}
