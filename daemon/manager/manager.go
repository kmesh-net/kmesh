/*
 * Copyright 2023 The Kmesh Authors.
 *
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

	"kmesh.net/kmesh/cmd/command"
	"kmesh.net/kmesh/pkg/bpf" // nolint
	"kmesh.net/kmesh/pkg/cni"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/options"
	"kmesh.net/kmesh/pkg/pid"
)

const (
	pkgSubsys = "manager"
)

var log = logger.NewLoggerField(pkgSubsys)

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
	defer func() {
		if err = pid.RemovePidFile(); err != nil {
			log.Errorf("failed to remove pid file, reason: %v", err)
		}
	}()

	if err = bpf.Start(); err != nil {
		fmt.Println(err)
		return
	}
	log.Info("bpf Start successful")
	defer bpf.Stop()

	if err = controller.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Info("controller Start successful")
	defer controller.Stop()

	if err = command.StartServer(); err != nil {
		log.Error(err)
		return
	}
	log.Info("command StartServer successful")
	defer func() {
		_ = command.StopServer()
	}()

	if err = cni.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Info("command Start cni successful")
	defer cni.Stop()

	setupCloseHandler()
}

func setupCloseHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGABRT, syscall.SIGTSTP)

	<-ch

	log.Warn("signal Notify exit")
}
