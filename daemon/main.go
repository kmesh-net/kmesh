/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description: 
 */

package main

import (
	"codehub.com/mesh/pkg/bpf"
	"codehub.com/mesh/pkg/logger"
	"codehub.com/mesh/pkg/option"
	"codehub.com/mesh/pkg/policy"
	"os"
	"os/signal"
	"syscall"
)

const (
	pkgSubsys = "daemon"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
	bpfProg *bpf.BpfProgram
)

func main() {
	var err error
	setupCloseHandler()

	cfg, _ := option.InitializeDaemonConfig()

	bpfProg, err = bpf.AttachCgroupSock(cfg.Cgroup2Path, cfg.BpffsPath)
	if err != nil {
		log.Error("AttachCgroupSock failed, ", err)
	}

	policy.ControlManager()
}

func setupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		bpfProg.Close()
		os.Exit(0)
	}()
}