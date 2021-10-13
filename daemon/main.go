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
	bpfObj *bpf.BpfObject
)

func main() {
	var err error
	setupCloseHandler()

	cfg, _ := option.InitializeDaemonConfig()
	info := &bpf.BpfInfo {
		BpffsPath:		cfg.BpffsPath,
		Cgroup2Path:	cfg.Cgroup2Path,
	}

	bpfObj, err = bpf.Load(info)
	if err != nil {
		log.Fatal("bpf Load failed, ", err)
	}
	if err = bpfObj.Setup(); err != nil {
		log.Error("bpf Setup failed, ", err)
	}
	if err := bpfObj.Attach(); err != nil {
		log.Fatal("bpf Attach failed, ", err)
	}

	policy.ControlManager()
}

func setupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		if err := bpfObj.Close(); err != nil {
			log.Error("bpf Close failed, ", err)
		}
		os.Exit(0)
	}()
}