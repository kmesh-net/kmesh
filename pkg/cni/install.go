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
 *
 * Author: bitcoffee
 * Create: 2023-11-19
 */

package cni

import (
	"kmesh.net/kmesh/pkg/bpf" // nolint
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("cni installer")

func addCniConfig() error {
	var err error
	if config.CniConfigChained {
		// "chained" is an cni type
		// information: www.cni.dev/docs/spec/#overview-1
		log.Infof("kmesh cni use chained\n")
		err = chainedKmeshCniPlugin()
		if err != nil {
			return err
		}
	} else {
		log.Error("currently kmesh only support chained cni mode\n")
	}
	return nil
}

func removeCniConfig() error {
	if config.CniConfigChained {
		return removeChainedKmeshCniPlugin()
	}
	return nil
}

func Start() error {
	if bpf.GetConfig().EnableKmesh {
		log.Info("start write CNI config\n")
		return addCniConfig()
	}
	return nil
}

func Stop() {
	if bpf.GetConfig().EnableKmesh {
		log.Info("start remove CNI config\n")
		if err := removeCniConfig(); err != nil {
			log.Error("remove CNI config failed, please remove manual")
		}
	}
}
