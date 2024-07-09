/*
 * Copyright 2024 The Kmesh Authors.
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
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/pkg/utils"
	"kmesh.net/kmesh/pkg/version"
)

const (
	NewStart = iota
	Restart
	Update
)

const (
	daemonSetName = "kmesh"
	namespace     = "kmesh-system"
)

var kmeshStartStatus int

func GetKmeshStartStatus() int {
	return kmeshStartStatus
}

func SetKmeshStartStatus(Status int) {
	kmeshStartStatus = Status
}

func GetDaemonset() bool {
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
	if GetDaemonset() {
		SetKmeshStartStatus(Restart)
	} else {
		SetKmeshStartStatus(NewStart)
	}
}

func SetStartStatus(versionMap *ebpf.Map) {
	var GitVersion [16]byte
	oldGitVersion := GetMap(versionMap, 0)
	copy(GitVersion[:], version.Get().GitVersion)
	log.Debugf("oldGitVersion:%v\nGitVersion:%v", oldGitVersion, GitVersion)
	if GitVersion == oldGitVersion {
		SetKmeshStartStatus(Restart)
	} else {
		SetKmeshStartStatus(Update)
	}
}

func cleanupMountPath() {
	if err := syscall.Unmount("/mnt/kmesh_cgroup2", 0); err != nil {
		log.Errorf("unmount /mnt/kmesh_cgroup2 error: %v", err)
	}

	if err := os.RemoveAll("/mnt/kmesh_cgroup2"); err != nil {
		log.Errorf("remove /mnt/kmesh_cgroup2 error: %v", err)
	}
}
