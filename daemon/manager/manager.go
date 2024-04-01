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
 */

// Package manager: kmesh daemon manager
package manager

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/cni"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/controller/dump"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/options"
)

const (
	pkgSubsys = "manager"
)

var log = logger.NewLoggerField(pkgSubsys)

func NewCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:          "kmesh-daemon",
		Short:        "Start kmesh daemon",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			printFlags(cmd.Flags())
			if err := options.ParseConfigs(); err != nil {
				return err
			}
			return Execute()
		},
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
	}

	addFlags(cmd)

	return cmd
}

// Execute start daemon manager process
func Execute() error {
	if err := bpf.Start(); err != nil {
		return err
	}
	log.Info("bpf Start successful")
	defer bpf.Stop()

	if err := controller.Start(); err != nil {
		return err
	}
	log.Info("controller Start successful")
	defer controller.Stop()

	if bpf.GetConfig().EnableKmesh {
		if err := dump.StartServer(); err != nil {
			return err
		}
		log.Info("dump StartServer successful")
		defer func() {
			_ = dump.StopServer()
		}()
	}

	if err := cni.Start(); err != nil {
		return err
	}
	log.Info("command Start cni successful")
	defer cni.Stop()

	setupCloseHandler()
	return nil
}

func setupCloseHandler() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP, syscall.SIGABRT, syscall.SIGTSTP)

	<-ch

	log.Warn("exiting...")
}

// printFlags print flags
func printFlags(flags *pflag.FlagSet) {
	flags.VisitAll(func(flag *pflag.Flag) {
		log.Infof("FLAG: --%s=%q", flag.Name, flag.Value)
	})
}

func addFlags(cmd *cobra.Command) {
	options.AttachFlags(cmd)
	cmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
}
