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

package controller

import (
	"context"
	"fmt"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/bypass"
	manage "kmesh.net/kmesh/pkg/controller/manage"
	"kmesh.net/kmesh/pkg/controller/security"
	"kmesh.net/kmesh/pkg/dns"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	stopCh      = make(chan struct{})
	ctx, cancle = context.WithCancel(context.Background())
	log         = logger.NewLoggerField("controller")
)

type Controller struct {
	mode                string
	bpfWorkloadObj      *bpf.BpfKmeshWorkload
	client              *XdsClient
	enableByPass        bool
	enableSecretManager bool
	bpfFsPath           string
	enableBpfLog        bool
}

func NewController(opts *options.BootstrapConfigs, bpfWorkloadObj *bpf.BpfKmeshWorkload, bpfFsPath string, enableBpfLog bool) *Controller {
	return &Controller{
		mode:                opts.BpfConfig.Mode,
		enableByPass:        opts.ByPassConfig.EnableByPass,
		bpfWorkloadObj:      bpfWorkloadObj,
		enableSecretManager: opts.SecretManagerConfig.Enable,
		bpfFsPath:           bpfFsPath,
		enableBpfLog:        enableBpfLog,
	}
}

func (c *Controller) Start() error {
	clientset, err := utils.GetK8sclient()
	if err != nil {
		return err
	}

	kmeshManageController, err := manage.NewKmeshManageController(clientset)
	if err != nil {
		return fmt.Errorf("failed to start kmesh manage controller: %v", err)
	}
	kmeshManageController.Run()

	log.Info("start kmesh manage controller successfully")

	if c.enableByPass {
		err = bypass.StartByPassController(clientset)
		if err != nil {
			return fmt.Errorf("failed to start bypass controller: %v", err)
		}

		log.Info("start bypass controller successfully")
	}

	if c.mode != constants.WorkloadMode && c.mode != constants.AdsMode {
		return nil
	}

	if c.enableBpfLog {
		if err := logger.StartRingBufReader(ctx, c.mode, c.bpfFsPath); err != nil {
			return fmt.Errorf("fail to start ringbuf reader: %v", err)
		}
	}
	c.client = NewXdsClient(c.mode, c.bpfWorkloadObj)

	if c.client.WorkloadController != nil {
		if c.enableSecretManager {
			secertManager, err := security.NewSecretManager()
			if err != nil {
				return fmt.Errorf("secretManager create failed: %v", err)
			}
			go secertManager.Run(stopCh)
			c.client.WorkloadController.Processor.SecretManager = secertManager
		}
		if c.client.WorkloadController.Rbac != nil {
			go c.client.WorkloadController.Rbac.Run(c.client.ctx, c.bpfWorkloadObj.SockOps.MapOfTuple, c.bpfWorkloadObj.XdpAuth.MapOfAuth)
		}
	}

	if c.client.AdsController != nil {
		dnsResolver, err := dns.NewDNSResolver(c.client.AdsController.Processor.Cache)
		if err != nil {
			return fmt.Errorf("dns resolver create failed: %v", err)
		}
		dnsResolver.StartDNSResolver(stopCh)
		c.client.AdsController.Processor.DnsResolverChan = dnsResolver.DnsResolverChan
	}

	return c.client.Run(stopCh)
}

func (c *Controller) Stop() {
	if c == nil {
		return
	}
	close(stopCh)
	cancle()
	if c.client != nil {
		c.client.Close()
	}
}

func (c *Controller) GetXdsClient() *XdsClient {
	return c.client
}
