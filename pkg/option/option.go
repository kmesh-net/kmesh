/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package option

import (
	"codehub.com/mesh/pkg/logger"
	"fmt"
)

const (
	pkgSubsys = "option"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

type DaemonConfig struct {
	Cgroup2Path	string
	BpffsPath	string
}

func InitializeDaemonConfig() (*DaemonConfig, error) {
	dc := &DaemonConfig {
		Cgroup2Path: "/mnt/cgroup2/",
		BpffsPath: "/sys/fs/bpf/",
	}
	return dc, nil
}

func (dc *DaemonConfig) String() string {
	return fmt.Sprintf("Cgroup2Path=%s, BpffsPath=%s", dc.Cgroup2Path, dc.BpffsPath)
}
