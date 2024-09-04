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

	"kmesh.net/kmesh/daemon/manager/dump"
	logcmd "kmesh.net/kmesh/daemon/manager/log"
	"kmesh.net/kmesh/daemon/manager/version"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/cni"
	"kmesh.net/kmesh/pkg/controller"
	"kmesh.net/kmesh/pkg/grpcdata"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/status"
)

const (
	pkgSubsys = "manager"
)

var log = logger.NewLoggerField(pkgSubsys)

func NewCommand() *cobra.Command {
	configs := options.NewBootstrapConfigs()
	cmd := &cobra.Command{
		Use:          "kmesh-daemon",
		Short:        "Start kmesh daemon",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			printFlags(cmd.Flags())
			if err := configs.ParseConfigs(); err != nil {
				return err
			}
			return Execute(configs)
		},
		FParseErrWhitelist: cobra.FParseErrWhitelist{
			UnknownFlags: true,
		},
	}

	addFlags(cmd, configs)

	// add sub commands
	cmd.AddCommand(version.NewCmd())
	cmd.AddCommand(dump.NewCmd())
	cmd.AddCommand(logcmd.NewCmd())

	return cmd
}

func ExecuteBpf(configs *options.BootstrapConfigs, bpfLoader *bpf.BpfLoader) error {
	go grpcdata.GrpcInitServer()
	if err := bpfLoader.Start(configs.BpfConfig); err != nil {
		return err
	}
	log.Info("bpf Start successful")
	defer bpfLoader.Stop()

	setupCloseHandler()
	return nil
}

func Execute(configs *options.BootstrapConfigs) error {
	bpfLoader := bpf.NewBpfLoader(configs.BpfConfig)

	component := getEnv("COMPONENT", "")

	if component == "bpf" {
		return ExecuteBpf(configs, bpfLoader)
	} else {
		return ExecuteDaemon(configs, bpfLoader)
	}
}

// Execute start daemon manager process
func ExecuteDaemon(configs *options.BootstrapConfigs, bpfLoader *bpf.BpfLoader) error {

	stopCh := make(chan struct{})
	defer close(stopCh)
	log.Infof("before init client")
	gc, conn := grpcdata.GrpcInitClient()
	if gc == nil {
		return nil
	}
	defer conn.Close()
	c := controller.NewController(configs, bpfLoader.GetBpfKmeshWorkload(), configs.BpfConfig.BpfFsPath, configs.BpfConfig.EnableBpfLog)
	if err := c.Start(stopCh); err != nil {
		return err
	}
	log.Info("controller Start successful")
	defer c.Stop()

	statusServer := status.NewServer(c.GetXdsClient(), configs, bpfLoader.GetBpfLogLevel())
	statusServer.StartServer()
	defer func() {
		_ = statusServer.StopServer()
	}()

	cniInstaller := cni.NewInstaller(configs.BpfConfig.Mode,
		configs.CniConfig.CniMountNetEtcDIR, configs.CniConfig.CniConfigName, configs.CniConfig.CniConfigChained)
	if err := cniInstaller.Start(); err != nil {
		return err
	}
	log.Info("command Start cni successful")
	defer cniInstaller.Stop()

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

func addFlags(cmd *cobra.Command, config *options.BootstrapConfigs) {
	config.AttachFlags(cmd)
	cmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
