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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/containernetworking/cni/libcni"

	"kmesh.net/kmesh/pkg/utils"
)

const (
	kmeshCniPluginName = "kmesh-cni"
	kmeshCniKubeConfig = "kmesh-cni-kubeconfig"
	MountedCNIBinDir   = "/opt/cni/bin"
)

func (i *Installer) getCniConfigPath() (string, error) {
	var confFile string
	if len(i.CniConfigName) != 0 {
		confFile = filepath.Join(i.CniMountNetEtcDIR, i.CniConfigName)
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
		files, err := libcni.ConfFiles(i.CniMountNetEtcDIR, []string{".conflist"})
		if err != nil {
			err = fmt.Errorf("failed to load conflist from dir :%v, : %v", i.CniMountNetEtcDIR, err)
			log.Error(err)
			return "", err
		}
		sort.Strings(files)
		var confList *libcni.NetworkConfigList = nil

		for _, file := range files {
			confList, err = libcni.ConfListFromFile(file)
			if err != nil {
				err = fmt.Errorf("failed to read conflist: %v, %v", file, err)
				log.Info(err)
				continue
			}
			if len(confList.Plugins) == 0 {
				log.Infof("file %s plugins is empty", confList.Name)
				continue
			} else {
				confFile = file
				break
			}
		}
		if confList == nil || len(confList.Plugins) == 0 {
			err = fmt.Errorf("can not found the valid cni config")
			log.Error(err)
			return "", err
		}
	}

	return confFile, nil
}

func (i *Installer) insertCNIConfig(oldconfig []byte, mode string) ([]byte, error) {
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

	kmeshIndex := -1
	for i, rawplugin := range plugins {
		plugin, ok := rawplugin.(map[string]interface{})
		if !ok {
			err = fmt.Errorf("failed to parser plugin\n")
			log.Error(err)
			return nil, err
		}
		if plugin["type"] == kmeshCniPluginName {
			kmeshIndex = i
			log.Infof("%s was installed but not cleaned up, but we would overwrite it", kmeshCniPluginName)
		}
	}

	kmeshConfig := map[string]string{}
	kubeconfigFilepath := filepath.Join(i.CniMountNetEtcDIR, kmeshCniKubeConfig)
	// add kmesh-cni configuration
	kmeshConfig["type"] = kmeshCniPluginName
	kmeshConfig["kubeConfig"] = kubeconfigFilepath
	kmeshConfig["mode"] = mode // provide mode here, so that kmesh-cni can decide how to run
	if kmeshIndex >= 0 {
		plugins[kmeshIndex] = kmeshConfig
		cniConfigMap["plugins"] = plugins
	} else {
		cniConfigMap["plugins"] = append(plugins, kmeshConfig)
	}

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

func (i *Installer) chainedKmeshCniPlugin(mode string, cniMountNetEtcDIR string) error {
	// Install binaries
	// Currently we _always_ do this, since the binaries do not live in a shared location
	// and we harm no one by doing so.
	err := copyBinary("/usr/bin/kmesh-cni", MountedCNIBinDir)
	if err != nil {
		return fmt.Errorf("copy binaries: %v", err)
	}

	// Install kubeconfig (if needed) - we write/update this in the shared node CNI bin dir,
	// which may be watched by other CNIs, and so we don't want to trigger writes to this file
	// unless it's missing or the contents are not what we expect.
	kubeconfigFilepath := filepath.Join(cniMountNetEtcDIR, kmeshCniKubeConfig)
	if err := maybeWriteKubeConfigFile(kubeconfigFilepath); err != nil {
		return fmt.Errorf("write kubeconfig: %v", err)
	}

	cniConfigFilePath, err := i.getCniConfigPath()
	if err != nil {
		return err
	}
	log.Infof("cni config file: %s", cniConfigFilePath)

	/*
	 TODO: add watcher for cniConfigFile
	*/

	existCNIConfig, err := os.ReadFile(cniConfigFilePath)
	if err != nil {
		err = fmt.Errorf("failed to read cni config file %v : %v", cniConfigFilePath, err)
		log.Error(err)
		return err
	}

	newCNIConfig, err := i.insertCNIConfig(existCNIConfig, mode)
	if err != nil {
		log.Error("failed to assemble cni config")
		return err
	}

	if len(newCNIConfig) == 0 {
		log.Infof("kmesh cni plugin is empty")
		return fmt.Errorf("kmesh cni config is not generated")
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

func (i *Installer) removeChainedKmeshCniPlugin() error {
	var err error
	var newCNIConfig []byte
	cniConfigFilePath, err := i.getCniConfigPath()
	if err != nil {
		return err
	}
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

	// remove kubeconfig file
	if kubeconfigFilepath := filepath.Join(i.CniMountNetEtcDIR, kmeshCniKubeConfig); fileExists(kubeconfigFilepath) {
		kubeconfigFilepath := filepath.Join(i.CniMountNetEtcDIR, kmeshCniKubeConfig)
		log.Infof("Removing Kmesh CNI kubeconfig file: %s", kubeconfigFilepath)
		if err := os.Remove(kubeconfigFilepath); err != nil {
			return err
		}
	}

	// remove cni binary
	if kmeshCNIBin := filepath.Join(MountedCNIBinDir, kmeshCniPluginName); fileExists(kmeshCNIBin) {
		log.Infof("Removing binary: %s", kmeshCNIBin)
		if err := os.Remove(kmeshCNIBin); err != nil {
			return err
		}
	}

	return nil
}

func copyBinary(filename string, targetDir string) error {
	_, binaryName := filepath.Split(filename)
	if err := utils.AtomicCopy(filename, targetDir, binaryName); err != nil {
		log.Errorf("Failed file copy of %s to %s: %s", filename, targetDir, err.Error())
		return err
	}
	log.Infof("Copied %s to %s.", filename, targetDir)
	return nil
}

func fileExists(filePath string) bool {
	_, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}
