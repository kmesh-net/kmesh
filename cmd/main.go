/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package main

import (
	"openeuler.io/mesh/cmd/command"
	"openeuler.io/mesh/pkg/logger"
)

const (
	pkgSubsys = "cmd"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

func main() {
	log.Debug("cmd test log")
	command.StartClient()
}
