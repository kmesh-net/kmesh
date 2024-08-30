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
 *
 * Author: bitcoffee
 * Create: 2023-11-19
 */

package cni

import (
	"fmt"
	"path/filepath"

	"github.com/fsnotify/fsnotify"

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
	Watcher           *fsnotify.Watcher
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
		log.Info("start write CNI config")
		err := i.addCniConfig()
		if err != nil {
			i.Stop()
			return err
		}

		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return fmt.Errorf("failed to create fsnotify watcher: %v", err)
		}
		i.Watcher = watcher

		if err = watcher.Add(ServiceAccountPath); err != nil {
			return fmt.Errorf("failed to add fsnotify watcher for path %s: %v", ServiceAccountPath, err)
		}

		// Start listening for events.
		go func() {
			log.Infof("start watching directory %s", ServiceAccountPath)

			for {
				select {
				case _, ok := <-watcher.Events:
					if !ok {
						log.Info("events channel of fsnotify watcher was closed")
						return
					}

					// NOTE: due to the update mechanism of service account path, try to update
					// kubeconfig of Kmesh cni regardless of any events.
					if err := maybeWriteKubeConfigFile(filepath.Join(i.CniMountNetEtcDIR, kmeshCniKubeConfig)); err != nil {
						log.Errorf("failed try to update kubeconfig of Kmesh cni: %v", err)
					}
				case err, ok := <-watcher.Errors:
					if !ok {
						log.Info("errors channel of fsnotify watcher was closed")
						return
					}
					log.Infof("error from errors channel of fsnotify watcher: %v", err)
				}
			}
		}()
	}
	return nil
}

func (i *Installer) Stop() {
	if i.Mode == constants.AdsMode || i.Mode == constants.WorkloadMode {
		log.Info("start remove CNI config")
		if err := i.removeCniConfig(); err != nil {
			log.Errorf("remove CNI config failed: %v, please remove manually", err)
		}
		if err := i.Watcher.Close(); err != nil {
			log.Errorf("failed to close fsnotify watcher: %v", err)
		}
		log.Info("remove CNI config done")
	}
}
