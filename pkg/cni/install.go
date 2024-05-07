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
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("cni installer")

func (i *Installer) addCniConfig() error {
	var err error
	if i.CniConfigChained {
		// "chained" is an cni type
		// information: www.cni.dev/docs/spec/#overview-1
		log.Infof("kmesh cni use chained\n")
		err = i.chainedKmeshCniPlugin(i.Mode, i.CniMountNetEtcDIR)
		if err != nil {
			return err
		}
	} else {
		log.Error("currently kmesh only support chained cni mode\n")
	}
	return nil
}

func (i *Installer) removeCniConfig() error {
	if i.CniConfigChained {
		return i.removeChainedKmeshCniPlugin()
	}
	return nil
}

type Installer struct {
	Mode              string
	CniMountNetEtcDIR string
	CniConfigName     string
	CniConfigChained  bool
}

func NewInstaller(mode string,
	cniMountNetEtcDIR string,
	cniConfigName string,
	cniConfigChained bool) *Installer {
	return &Installer{
		Mode:              mode,
		CniMountNetEtcDIR: cniMountNetEtcDIR,
		CniConfigName:     cniConfigName,
		CniConfigChained:  cniConfigChained,
	}
}

func (i *Installer) Start() error {
	if i.Mode == constants.AdsMode || i.Mode == constants.WorkloadMode {
		log.Info("start write CNI config\n")
		return i.addCniConfig()
	}
	return nil
}

func (i *Installer) Stop() {
	if i.Mode == constants.AdsMode || i.Mode == constants.WorkloadMode {
		log.Info("start remove CNI config\n")
		if err := i.removeCniConfig(); err != nil {
			log.Error("remove CNI config failed, please remove manual")
		}
	}
}
