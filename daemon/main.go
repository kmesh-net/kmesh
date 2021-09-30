/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package main

import (
	"codehub.com/mesh/pkg/logger"
	"codehub.com/mesh/pkg/bpf"
)

const (
	daemonSubsys = "daemon"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, daemonSubsys)
)

func main() {
	log.Debug("test log")
	bpf.Test("test bpf")
}
