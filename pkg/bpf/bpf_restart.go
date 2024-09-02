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

package bpf

import (
	"context"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"istio.io/pkg/env"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/utils"
	"kmesh.net/kmesh/pkg/version"
)

/*
 * Indicates how to start kmesh on the next launch or how to close kmesh.
 * Start Kmesh:
 *		Normal: a normal new start
 *		Restart: reusing the previous kmesh configuration
 *		Update: upgrading kmesh and reusing part of previous kmesh configuration
 * Exit Kmesh:
 *		Normal: normal close, cleanup all the bpf prog and maps
 *		Restart: not clean kmesh configuration and bpf map, for next launch
 *		Update: not supported yet
 */

type StartType uint8

const (
	Normal StartType = iota
	Restart
	Update
)

// kmeshStartType is used during bootstrap to indicate how to initiate bpf prog and maps
var kmeshStartType StartType

// kmeshStartType is used during exit to indicate how to cleanup bpf prog and maps
var kmeshExitType StartType

func GetStartType() StartType {
	return kmeshStartType
}

func SetStartType(Status StartType) {
	kmeshStartType = Status
}

func SetExitType() {
	kmeshExitType = inferNextStartType()
}

func GetExitType() StartType {
	return kmeshExitType
}

func inferNextStartType() StartType {
	clientset, err := utils.GetK8sclient()
	if err != nil {
		return Normal
	}
	podName := strings.Split(env.Register("POD_NAME", "", "").Get(), "-")
	daemonSetName := podName[0]
	daemonSetNamespace := env.Register("POD_NAMESPACE", "", "").Get()
	log.Infof("trying to get daemonSet %s in namespace %s", daemonSetName, daemonSetNamespace)
	daemonSet, err := clientset.AppsV1().DaemonSets(daemonSetNamespace).Get(context.TODO(), daemonSetName, metav1.GetOptions{})
	if err == nil {
		log.Infof("found daemonSet %s in namespace %s", daemonSet.Name, daemonSet.Namespace)
		return Restart
	}
	log.Infof("unable to find daemonSet %s in namespace %s: %v ", daemonSetName, daemonSetNamespace, err)
	return Normal
}

func SetStartStatus(versionMap *ebpf.Map) {
	var GitVersion uint32
	hash.Reset()
	hash.Write([]byte(version.Get().GitVersion))
	GitVersion = hash.Sum32()
	oldGitVersion := getOldVersionFromMap(versionMap, 0)
	log.Infof("oldGitVersion: %v newGitVersion: %v", oldGitVersion, GitVersion)
	if GitVersion == oldGitVersion {
		log.Infof("kmesh start with Restart, load bpf maps and prog from last")
		SetStartType(Restart)
	} else if oldGitVersion == 0 {
		// version not found, it is a fresh start
		log.Infof("kmesh start with Normal")
		SetStartType(Normal)
	} else {
		log.Infof("kmesh start with Update")
		SetStartType(Update)
	}
}

func CleanupBpfMap() {
	err := syscall.Unmount(constants.Cgroup2Path, 0)
	if err != nil {
		fmt.Println("unmount /mnt/kmesh_cgroup2 error: ", err)
	}
	err = syscall.Unmount(constants.BpfFsPath, 0)
	if err != nil {
		fmt.Println("unmount /sys/fs/bpf error: ", err)
	}
	err = os.RemoveAll(constants.Cgroup2Path)
	if err != nil {
		fmt.Println("remove /mnt/kmesh_cgroup2 error: ", err)
	}
}
