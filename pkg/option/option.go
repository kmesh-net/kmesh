/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package option

import (
	"fmt"
)

const (
	ClientModeKube = "kubernetes"
	ClientModeEnvoy = "envoy"
)

type BpfConfig struct {
	BpffsPath	string
	Cgroup2Path	string
}
type ClientConfig struct {
	ClientMode		string
	KubeInCluster	bool
}

type DaemonConfig struct {
	BpfConfig
	ClientConfig
}

func InitializeDaemonConfig() (DaemonConfig, error) {
	dc := DaemonConfig{}

	dc.BpfConfig.BpffsPath = "/sys/fs/bpf/"
	dc.BpfConfig.Cgroup2Path = "/mnt/cgroup2/"

	dc.ClientConfig.ClientMode = ClientModeKube
	dc.ClientConfig.KubeInCluster = false

	return dc, nil
}

func (dc *DaemonConfig) String() string {
	return fmt.Sprintf("%#v", *dc)
}
