/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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

 * Author: LemmyHuang
 * Create: 2021-10-09
 */

// Package manager: kmesh daemon manager
package manager

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"openeuler.io/mesh/cmd/command"
	"openeuler.io/mesh/pkg/bpf"
	"openeuler.io/mesh/pkg/controller"
	"openeuler.io/mesh/pkg/logger"
	"openeuler.io/mesh/pkg/options"
	"openeuler.io/mesh/pkg/pid"
)

const (
	pkgSubsys = "manager"
)

var (
	log = logger.NewLoggerField(pkgSubsys)
)

// Execute start daemon manager process
func Execute() {
	var err error

	if err = options.InitDaemonConfig(); err != nil {
		log.Error(err)
		return
	}
	log.Info("options InitDaemonConfig successful")

	if err = pid.CreatePidFile(); err != nil {
		log.Errorf("failed to start, reason: %v", err)
		return
	}
	defer pid.RemovePidFile()

	if err = bpf.Start(); err != nil {
		fmt.Println(err)
		return
	}
	log.Info("bpf Start successful")

	if err = controller.Start(); err != nil {
		log.Error(err)
		bpf.Stop()
		return
	}
	log.Info("controller Start successful")

	if err = command.StartServer(); err != nil {
		log.Error(err)
		controller.Stop()
		bpf.Stop()
		return
	}
	log.Info("command StartServer successful")

	setupCloseHandler()
	return
}

func setupCloseHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGABRT, syscall.SIGTSTP)

	<-ch
	command.StopServer()
	controller.Stop()
	bpf.Stop()

	log.Warn("signal Notify exit")
}
