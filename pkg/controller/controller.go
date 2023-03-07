/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
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

package controller

import (
	"openeuler.io/mesh/pkg/bpf"
	"openeuler.io/mesh/pkg/controller/envoy"
	"openeuler.io/mesh/pkg/controller/interfaces"
)

var (
	stopCh     = make(chan struct{})
	client     interfaces.ClientFactory
)

func Start() error {
	var err error

	client, err = config.NewClient()
	if err != nil {
		return err
	}

	return client.Run(stopCh)
}

func Stop() {
	var obj struct{}
	stopCh <- obj
	close(stopCh)
	client.Close()
}

func GetAdsClient() *envoy.AdsClient {
	if !bpf.GetConfig().EnableKmesh {
		return nil
	}
	return client.(*envoy.AdsClient)
}

func IsAdsEnable() bool {
	return envoy.GetConfig().EnableAds
}
