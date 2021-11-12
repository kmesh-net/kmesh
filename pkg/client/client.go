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

package client

import (
	"fmt"
	xds "openeuler.io/mesh/pkg/client/envoy"
	apiserver "openeuler.io/mesh/pkg/client/kubernetes"
	"openeuler.io/mesh/pkg/client/yaml"
	"openeuler.io/mesh/pkg/option"
)

type Interface interface {
	Init(config interface{})
	Start() error
}

func Start() error {

	go yaml.Run()

	switch option.GetClientConfig().ClientMode {
	case option.ClientModeKube:
		go apiserver.Run()
	case option.ClientModeEnvoy:
		go xds.Run()
	default:
		return fmt.Errorf("invalid client mode, %s", option.GetClientConfig().ClientMode)
	}

	return nil
}