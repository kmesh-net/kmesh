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
	pkgSubsys = "client"
)

var (
	log = logger.DefaultLogger.WithField(logger.LogSubsys, pkgSubsys)
)

func Start() error {
	switch option.GetClientConfig().ClientMode {
	case option.ClientModeKube:
		go func() {
			err := apiserver.Run()
			log.Error(err)
		}()
	case option.ClientModeEnvoy:
		go func() {
			err := xds.Run()
			log.Error(err)
		}()
	default:
		return fmt.Errorf("invalid client mode, %s", option.GetClientConfig().ClientMode)
	}

	return nil
}