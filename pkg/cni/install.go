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
 */

package cni

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"istio.io/istio/pkg/filewatcher"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerScope("cni installer")

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
	Mode               string
	CniMountNetEtcDIR  string
	CniConfigName      string
	CniConfigChained   bool
	ServiceAccountPath string

	Watcher filewatcher.FileWatcher
}

func NewInstaller(mode string,
	cniMountNetEtcDIR string,
	cniConfigName string,
	cniConfigChained bool,
	serviceAccountPath string) *Installer {
	return &Installer{
		Mode:               mode,
		CniMountNetEtcDIR:  cniMountNetEtcDIR,
		CniConfigName:      cniConfigName,
		CniConfigChained:   cniConfigChained,
		ServiceAccountPath: serviceAccountPath,
		Watcher:            filewatcher.NewWatcher(),
	}
}

func (i *Installer) WatchServiceAccountToken() error {
	tokenPath := i.ServiceAccountPath + "/token"
	if err := i.Watcher.Add(tokenPath); err != nil {
		return fmt.Errorf("failed to add %s to file watcher: %v", tokenPath, err)
	}

	// Start listening for events.
	go func() {
		log.Infof("start watching file %s", tokenPath)

		var timerC <-chan time.Time
		for {
			select {
			case <-timerC:
				timerC = nil

				if err := maybeWriteKubeConfigFile(i.ServiceAccountPath, filepath.Join(i.CniMountNetEtcDIR, kmeshCniKubeConfig)); err != nil {
					log.Errorf("failed try to update Kmesh cni kubeconfig: %v", err)
				}

			case event := <-i.Watcher.Events(tokenPath):
				log.Debugf("got event %s", event.String())

				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					if timerC == nil {
						timerC = time.After(100 * time.Millisecond)
					}
				}
			case err := <-i.Watcher.Errors(tokenPath):
				if err != nil {
					log.Errorf("error from errors channel of file watcher: %v", err)
					return
				}
			}
		}
	}()

	return nil
}

func (i *Installer) Start() error {
	if i.Mode == constants.KernelNativeMode || i.Mode == constants.DualEngineMode {
		log.Info("start write CNI config")
		err := i.addCniConfig()
		if err != nil {
			i.Stop()
			return err
		}

		if err := i.WatchServiceAccountToken(); err != nil {
			return err
		}
	}

	return nil
}

func (i *Installer) Stop() {
	if i.Mode == constants.KernelNativeMode || i.Mode == constants.DualEngineMode {
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
