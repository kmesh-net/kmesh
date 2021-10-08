/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package bpf

import (
	"codehub.com/mesh/pkg/logger"
	//"github.com/cilium/ebpf"
)

const (
	pkgSubsys = "bpf"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

func Test(s string) {
	log.Debug(s)
}
