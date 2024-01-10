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

package cni_plg

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"kmesh.net/kmesh/pkg/utils"

	"github.com/containernetworking/cni/libcni"
)

const (
	kmeshCniPluginName = "kmesh-cni"
	kmeshCniKubeConfig = "kmesh-cni-kubeconfig"
	MountedCNIBinDir   = "/opt/cni/bin"
)

var cniConfigFilePath string

func getCniConfigPath() (string, error) {
	var confFile string
	if len(config.CniConfigName) != 0 {
		confFile = filepath.Join(config.CniMountNetEtcDIR, config.CniConfigName)
		confList, err := libcni.ConfListFromFile(confFile)
		if err != nil {
			err = fmt.Errorf("failed to read conflist %v : %v", confFile, err)
			log.Error(err)
			return "", err
		}
		if len(confList.Plugins) == 0 {
			err = fmt.Errorf("file %s plugins is empty\n", confList.Name)
			log.Error(err)
			return "", err
		}
	} else {
		files, err := libcni.ConfFiles(config.CniMountNetEtcDIR, []string{".conflist"})
		if err != nil {
			err = fmt.Errorf("failed to load conflist from dir :%v, : %v", config.CniMountNetEtcDIR, err)
			log.Error(err)
			return "", err
		}
		sort.Strings(files)
		var confList *libcni.NetworkConfigList = nil

		for _, confFile = range files {
			confList, err = libcni.ConfListFromFile(confFile)
			if err != nil {
				err = fmt.Errorf("failed to read conflist: %v, %v", confFile, err)
				log.Info(err)
				continue
			}
			if len(confList.Plugins) == 0 {
				log.Infof("file %s plugins is empty\n", confList.Name)
				continue
			} else {
				break
			}
		}
		if confList == nil || len(confList.Plugins) == 0 {
			err = fmt.Errorf("can not found the valid cni config!\n")
			log.Error(err)
			return "", err
		}
	}

	return confFile, nil
}

func insertCNIConfig(oldconfig []byte) ([]byte, error) {
	var cniConfigMap map[string]interface{}
	err := json.Unmarshal(oldconfig, &cniConfigMap)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal json: %v", err)
		log.Error(err)
		return nil, err
	}

	plugins, ok := cniConfigMap["plugins"].([]interface{})
	if !ok {
		err = fmt.Errorf("can not found valid plugin list in insert cni config\n")
		log.Error(err)
		return nil, err
	}

	for _, rawplugin := range plugins {
		plugin, ok := rawplugin.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("failed to parser plugin\n")
			log.Error(err)
			return nil, err
		}
		if plugin["type"] == kmeshCniPluginName {
			return nil, nil
		}
	}

	kmeshConfig := map[string]string{}
	// add kmesh-cni configuration
	kmeshConfig["type"] = kmeshCniPluginName
	kmeshConfig["kubeConfig"] = kmeshCniKubeConfig
	cniConfigMap["plugins"] = append(plugins, kmeshConfig)

	byte, err := json.MarshalIndent(cniConfigMap, "", "  ")
	if err != nil {
		err = fmt.Errorf("failed to marshal json: %v", err)
		log.Error(err)
		return nil, err
	}

	return byte, nil
}

func deleteCNIConfig(oldconfig []byte) ([]byte, error) {
	var cniConfigMap map[string]interface{}
	var index int
	var rawplugin interface{}
	var foundKmeshPlugin bool = false

	err := json.Unmarshal(oldconfig, &cniConfigMap)
	if err != nil {
		err = fmt.Errorf("failed to unmarshal json: %v", err)
		log.Error(err)
		return nil, err
	}

	plugins, ok := cniConfigMap["plugins"].([]interface{})
	if !ok {
		err = fmt.Errorf("can not valid plugin list in delete cni config\n")
		log.Error(err)
		return nil, err
	}

	for index, rawplugin = range plugins {
		plugin, ok := rawplugin.(map[string]interface{})
		if !ok {
			continue
		}
		if plugin["type"] == kmeshCniPluginName {
			foundKmeshPlugin = true
			break
		}
	}

	if foundKmeshPlugin {
		newplugins := append(plugins[:index], plugins[index+1:]...)
		cniConfigMap["plugins"] = newplugins
	}

	byte, err := json.MarshalIndent(cniConfigMap, "", "  ")
	if err != nil {
		err = fmt.Errorf("failed to marshal json: %v", err)
		log.Error(err)
		return nil, err
	}

	return byte, nil
}

func chainedKmeshCniPlugin() error {
	var err error
	var newCNIConfig []byte
	cniConfigFilePath, err = getCniConfigPath()
	if err != nil {
		return err
	}

	/*
	 TODO: add watcher for cniConfigFile
	*/

	existCNIConfig, err := os.ReadFile(cniConfigFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read cni config file %v : %v", cniConfigFilePath, err)
		log.Error(err)
		return err
	}

	// TODO(hzxuzhonghu): install kmesh cni binary, currently it is installed from start_kmesh.sh

	// Install kubeconfig (if needed) - we write/update this in the shared node CNI bin dir,
	// which may be watched by other CNIs, and so we don't want to trigger writes to this file
	// unless it's missing or the contents are not what we expect.
	if err := maybeWriteKubeConfigFile(); err != nil {
		return fmt.Errorf("write kubeconfig: %v", err)
	}

	newCNIConfig, err = insertCNIConfig(existCNIConfig)
	if err != nil {
		log.Error("failed to assemble cni config")
		return err
	}

	fileInfo, err := os.Stat(cniConfigFilePath)
	if err != nil {
		log.Errorf("failed to read cni config file permissions: %v", err)
		return err
	}

	err = utils.AtomicWrite(cniConfigFilePath, newCNIConfig, fileInfo.Mode().Perm())
	if err != nil {
		log.Errorf("failed to write cni config file")
		return err
	}

	return nil
}

func removeChainedKmeshCniPlugin() error {
	var err error
	var newCNIConfig []byte
	existCNIConfig, err := os.ReadFile(cniConfigFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read cni config file %v : %v", cniConfigFilePath, err)
		log.Error(err)
		return err
	}

	newCNIConfig, err = deleteCNIConfig(existCNIConfig)
	if err != nil {
		log.Error("failed to delete cni config")
		return err
	}

	fileInfo, err := os.Stat(cniConfigFilePath)
	if err != nil {
		log.Errorf("failed to read cni config file permissions: %v", err)
		return err
	}

	err = utils.AtomicWrite(cniConfigFilePath, newCNIConfig, fileInfo.Mode().Perm())
	if err != nil {
		log.Errorf("failed to write cni config file")
		return err
	}

	return nil
}
