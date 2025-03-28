/*
 * Copyright The Kmesh Authors.
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

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf"
	bpfads "kmesh.net/kmesh/pkg/bpf/ads"
	bpfwl "kmesh.net/kmesh/pkg/bpf/workload"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/bypass"
	"kmesh.net/kmesh/pkg/controller/encryption/ipsec"
	manage "kmesh.net/kmesh/pkg/controller/manage"
	"kmesh.net/kmesh/pkg/controller/security"
	"kmesh.net/kmesh/pkg/kolog"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
	helper "kmesh.net/kmesh/pkg/utils"
)

var (
	ctx, cancel = context.WithCancel(context.Background())
	log         = logger.NewLoggerScope("controller")
)

type Controller struct {
	mode                string
	bpfAdsObj           *bpfads.BpfAds
	bpfWorkloadObj      *bpfwl.BpfWorkload
	client              *XdsClient
	ipsecController     *ipsec.IPSecController
	enableByPass        bool
	enableSecretManager bool
	bpfConfig           *options.BpfConfig
	loader              *bpf.BpfLoader
}

func NewController(opts *options.BootstrapConfigs, bpfLoader *bpf.BpfLoader) *Controller {
	return &Controller{
		mode:                opts.BpfConfig.Mode,
		enableByPass:        opts.ByPassConfig.EnableByPass,
		bpfAdsObj:           bpfLoader.GetBpfKmesh(),
		bpfWorkloadObj:      bpfLoader.GetBpfWorkload(),
		enableSecretManager: opts.SecretManagerConfig.Enable,
		bpfConfig:           opts.BpfConfig,
		loader:              bpfLoader,
	}
}

func (c *Controller) Start(stopCh <-chan struct{}) error {
	var err error
	var kmeshManageController *manage.KmeshManageController
	var tcFd int

	clientset, err := kube.CreateKubeClient("")
	if err != nil {
		return err
	}

	if c.bpfConfig.EnableIPsec {
		var kniMap *ebpf.Map
		var decryptProg *ebpf.Program
		if c.mode == constants.KernelNativeMode {
			kniMap = c.bpfAdsObj.Tc.KmeshTcMarkEncryptObjects.KmNodeinfo
			tcFd = c.bpfAdsObj.Tc.TcMarkEncrypt.FD()
			decryptProg = c.bpfAdsObj.Tc.KmeshTcMarkDecryptObjects.TcMarkDecrypt
		} else {
			kniMap = c.bpfWorkloadObj.Tc.KmeshTcMarkEncryptObjects.KmNodeinfo
			tcFd = c.bpfWorkloadObj.Tc.TcMarkEncrypt.FD()
			decryptProg = c.bpfWorkloadObj.Tc.KmeshTcMarkDecryptObjects.TcMarkDecrypt
		}
		c.ipsecController, err = ipsec.NewIPsecController(clientset, kniMap, decryptProg)
		if err != nil {
			return fmt.Errorf("failed to new IPsec controller, %v", err)
		}
		go c.ipsecController.Run(stopCh)
		log.Info("start IPsec controller successfully")
	} else {
		tcFd = -1
	}

	if c.mode == constants.DualEngineMode {
		var secertManager *security.SecretManager
		if c.enableSecretManager {
			secertManager, err = security.NewSecretManager()
			if err != nil {
				return fmt.Errorf("secretManager create failed: %v", err)
			}
			go secertManager.Run(stopCh)
		}
		kmeshManageController, err = manage.NewKmeshManageController(clientset, secertManager, c.bpfWorkloadObj.XdpAuth.XdpAuthz.FD(), tcFd, c.mode)
	} else {
		kolog.KmeshModuleLog(stopCh)
		kmeshManageController, err = manage.NewKmeshManageController(clientset, nil, -1, tcFd, c.mode)
	}
	if err != nil {
		return fmt.Errorf("failed to start kmesh manage controller: %v", err)
	}
	go kmeshManageController.Run(stopCh)
	log.Info("start kmesh manage controller successfully")

	if c.enableByPass {
		c := bypass.NewByPassController(clientset)
		go c.Run(stopCh)
		log.Info("start bypass controller successfully")
	}

	if c.mode != constants.DualEngineMode && c.mode != constants.KernelNativeMode {
		return nil
	}

	// only support bpf log when kernel version >= 5.13
	if !helper.KernelVersionLowerThan5_13() {
		if c.mode == constants.KernelNativeMode {
			logger.StartLogReader(ctx, c.bpfAdsObj.SockConn.KmLogEvent)
		} else if c.mode == constants.DualEngineMode {
			logger.StartLogReader(ctx, c.bpfWorkloadObj.SockConn.KmLogEvent)
		}
	}

	// kmeshConfigMap.Monitoring initialized to uint32(1).
	// If the startup parameter is false, update the kmeshConfigMap.
	if !c.bpfConfig.EnableMonitoring {
		if err := c.loader.UpdateEnableMonitoring(constants.DISABLED); err != nil {
			return fmt.Errorf("Failed to update config in order to start metric: %v", err)
		}
	}

	c.client = NewXdsClient(c.mode, c.bpfAdsObj, c.bpfWorkloadObj, c.bpfConfig.EnableMonitoring, c.bpfConfig.EnableProfiling)

	if c.client.WorkloadController != nil {
		c.client.WorkloadController.Run(ctx)
	} else {
		c.client.AdsController.StartDnsController(stopCh)
	}

	return c.client.Run(stopCh)
}

func (c *Controller) Stop() {
	if c == nil {
		return
	}
	cancel()
	if c.bpfConfig.EnableIPsec {
		c.ipsecController.Stop()
	}
	if c.client != nil {
		c.client.Close()
	}
}

func (c *Controller) GetXdsClient() *XdsClient {
	return c.client
}
