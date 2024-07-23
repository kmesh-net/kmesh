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
	"syscall"

	"github.com/cilium/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/utils"
	"kmesh.net/kmesh/pkg/version"
)

// Indicates how to start kmesh on the next launch or how to close kmesh.
// Start:
// Normal: a normal new start
// Restart: reusing the previous kmesh configuration
// Update: upgrading kmesh and reusing part of previous kmesh configuration
// Close:
// Normal: normal close
// Restart: not clean kmesh configuration, for next launch
// Update: not clean part of kmesh configuration, for next launch
const (
	Normal = iota
	Restart
	Update
)

const (
	daemonSetName = "kmesh"
	namespace     = "kmesh-system"
)

var kmeshStatus int

func GetKmeshStatus() int {
	return kmeshStatus
}

func SetKmeshStatus(Status int) {
	kmeshStatus = Status
}

func InferRestartStatus() bool {
	clientset, err := utils.GetK8sclient()
	if err != nil {
		return false
	}

	daemonSet, err := clientset.AppsV1().DaemonSets(namespace).Get(context.TODO(), daemonSetName, metav1.GetOptions{})
	if err == nil {
		log.Debugf("Found DaemonSet %s in namespace %s\n", daemonSet.Name, daemonSet.Namespace)
		return true
	}
	return false
}

func SetCloseStatus() {
	if InferRestartStatus() {
		SetKmeshStatus(Restart)
	} else {
		SetKmeshStatus(Normal)
	}
}

func SetStartStatus(versionMap *ebpf.Map) {
	var GitVersion [16]byte
	oldGitVersion := GetMap(versionMap, 0)
	copy(GitVersion[:], version.Get().GitVersion)
	log.Debugf("oldGitVersion:%v\nGitVersion:%v", oldGitVersion, GitVersion)
	if GitVersion == oldGitVersion {
		SetKmeshStatus(Restart)
	} else {
		SetKmeshStatus(Update)
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
