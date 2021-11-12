/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * Description:
 */

package client

import (
	xds "openeuler.io/mesh/pkg/client/envoy"
	apiserver "openeuler.io/mesh/pkg/client/kubernetes"
	"openeuler.io/mesh/pkg/client/yaml"
	"openeuler.io/mesh/pkg/option"
	"fmt"
)

type Interface interface {
	Init(config interface{})
	Start() error
}

func Start(cfg *option.ClientConfig) error {

	go yaml.Run()

	switch cfg.ClientMode {
	case option.ClientModeKube:
		go apiserver.Run(cfg)
	case option.ClientModeEnvoy:
		go xds.Run(cfg)
	default:
		return fmt.Errorf("invalid client mode, %s", cfg.ClientMode)
	}

	return nil
}