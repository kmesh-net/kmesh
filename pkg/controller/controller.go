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
	"fmt"

	"kmesh.net/kmesh/pkg/bpf"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/bypass"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	stopCh = make(chan struct{})
	log    = logger.NewLoggerField("controller")
)

type Controller struct {
	mode           string
	bpfWorkloadObj *bpf.BpfKmeshWorkload
	client         *XdsClient
}

func NewController(mode string, bpfWorkloadObj *bpf.BpfKmeshWorkload) *Controller {
	return &Controller{
		mode:           mode,
		bpfWorkloadObj: bpfWorkloadObj,
	}
}

func (c *Controller) Start() error {
	if c.mode != constants.WorkloadMode && c.mode != constants.AdsMode {
		return nil
	}

	c.client = NewXdsClient(c.mode, c.bpfWorkloadObj)

	clientset, err := utils.GetK8sclient()
	if err != nil {
		panic(err)
	}

	// TODO(hzxuzhonghu): move before xds client inititation
	err = bypass.StartByPassController(clientset)
	if err != nil {
		return fmt.Errorf("failed to start bypass controller: %v", err)
	}

	return c.client.Run(stopCh)
}

func (c *Controller) Stop() {
	if c == nil {
		return
	}
	close(stopCh)
	if c.client != nil {
		c.client.Close()
	}
}

func (c *Controller) GetXdsClient() *XdsClient {
	return c.client
}
