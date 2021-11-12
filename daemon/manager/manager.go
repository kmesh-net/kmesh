/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description:
 */

package manager

import (
	"codehub.com/mesh/cmd/command"
	"codehub.com/mesh/pkg/bpf"
	"codehub.com/mesh/pkg/client"
	"codehub.com/mesh/pkg/logger"
	"codehub.com/mesh/pkg/option"
	"os"
	"os/signal"
	"syscall"
)
const (
	pkgSubsys = "manager"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
	bpfObj bpf.BpfObject
	config option.DaemonConfig
)

func Execute() {
	var err error

	config, _ = option.InitializeDaemonConfig()
	log.Debugf("%#v", config)

	bpfObj, err = bpf.Start(&config.BpfConfig)
	if err != nil {
		log.Error(err)
		return
	}
	defer bpfObj.Detach()
	setupCloseHandler()

	err = client.Start(&config.ClientConfig)
	if err != nil {
		log.Error(err)
	}

	command.StartServer()
	return
}

func setupCloseHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-c
		bpfObj.Detach()
		os.Exit(0)
	}()
}