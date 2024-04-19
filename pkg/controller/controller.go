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
	"kmesh.net/kmesh/pkg/controller/bypass"
	"kmesh.net/kmesh/pkg/controller/interfaces"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	stopCh    = make(chan struct{})
	client    interfaces.ClientFactory
	log       = logger.NewLoggerField("controller")
	bpfConfig = bpf.GetConfig()
)

func Start() error {
	if !bpfConfig.AdsEnabled() && !bpfConfig.WdsEnabled() {
		return fmt.Errorf("controller start failed")
	}

	client = NewXdsClient()

	clientset, err := utils.GetK8sclient()
	if err != nil {
		panic(err)
	}

	bypass.StartByPassController(clientset)

	return client.Run(stopCh)
}

func Stop() {
	var obj struct{}
	stopCh <- obj
	close(stopCh)
	client.Close()
}

func GetXdsClient() *XdsClient {
	return client.(*XdsClient)
}
