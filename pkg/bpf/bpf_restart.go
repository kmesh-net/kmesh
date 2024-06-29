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
 */

package bpf

import (
	"context"
	"os"
	"syscall"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"kmesh.net/kmesh/pkg/utils"
)

const (
	NewStart = iota
	Restart
	Update
	Reload
)

func GetDaemonset() bool {
	clientset, err := utils.GetK8sclient()
	if err != nil {
		return false
	}
	_, err = clientset.AppsV1().DaemonSets("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		log.Printf("daemonset err:%v", err)
		return false
	}
	return true
}

func cleanupMountPath() {
	if err := syscall.Unmount("/mnt/kmesh_cgroup2", 0); err != nil {
		log.Errorf("unmount /mnt/kmesh_cgroup2 error: ", err)
	}

	if err := os.RemoveAll("/mnt/kmesh_cgroup2"); err != nil {
		log.Errorf("remove /mnt/kmesh_cgroup2 error: ", err)
	}

}