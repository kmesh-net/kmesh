/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2021-10-09
 */

package controller

import (
	"fmt"
	xds "openeuler.io/mesh/pkg/controller/envoy"
	apiserver "openeuler.io/mesh/pkg/controller/kubernetes"
	"openeuler.io/mesh/pkg/logger"
	"openeuler.io/mesh/pkg/option"
)

const (
	pkgSubsys = "controller"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
	stopCh = make(chan struct{})
)

func Start() error {
	var err error = nil

	switch option.GetClientConfig().ClientMode {
	case option.ClientModeKube:
		err = apiserver.Run(stopCh)
	case option.ClientModeEnvoy:
		err = xds.Run(stopCh)
	default:
		return fmt.Errorf("invalid client mode, %s", option.GetClientConfig().ClientMode)
	}

	return err
}

func Quit() {
	var obj struct{}
	stopCh <- obj
	close(stopCh)
}