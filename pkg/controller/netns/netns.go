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

package netns

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	nd "istio.io/istio/cni/pkg/nodeagent"
	"istio.io/istio/pkg/util/sets"
	"istio.io/pkg/log"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	FS embed.FS
)

func GetPodNSpath(pod *corev1.Pod) (string, error) {
	res, err := FindNetnsForPod(pod)
	if err != nil {
		return "", err
	}
	res = path.Join("/host/proc", res)
	return res, nil
}

func builtinOrDir(dir string) fs.FS {
	if dir == "" {
		return FS
	}
	return os.DirFS(dir)
}

func FindNetnsForPod(pod *corev1.Pod) (string, error) {
	netnsObserved := sets.New[uint64]()
	fd := builtinOrDir("/host/proc")

	entries, err := fs.ReadDir(fd, ".")
	if err != nil {
		return "", err
	}

	desiredUID := pod.UID
	for _, entry := range entries {
		res, err := processEntry(fd, netnsObserved, desiredUID, entry)
		if err != nil {
			log.Debugf("error processing entry: %s %v", entry.Name(), err)
			continue
		}
		if res != "" {
			return res, nil
		}
	}
	return "", fmt.Errorf("No matching network namespace found")
}

func isNotNumber(r rune) bool {
	return r < '0' || r > '9'
}

func isProcess(entry fs.DirEntry) bool {
	if !entry.IsDir() {
		return false
	}

	if strings.IndexFunc(entry.Name(), isNotNumber) != -1 {
		return false
	}
	return true
}

// copied from https://github.com/istio/istio/blob/master/cni/pkg/nodeagent/podcgroupns.go
func processEntry(proc fs.FS, netnsObserved sets.Set[uint64], filter types.UID, entry fs.DirEntry) (string, error) {
	if !isProcess(entry) {
		return "", nil
	}

	netnsName := path.Join(entry.Name(), "ns", "net")
	fi, err := fs.Stat(proc, netnsName)
	if err != nil {
		return "", err
	}

	inode, err := nd.GetInode(fi)
	if err != nil {
		return "", err
	}
	if _, ok := netnsObserved[inode]; ok {
		log.Debugf("netns: %d already processed. skipping", inode)
		return "", nil
	}

	cgroup, err := proc.Open(path.Join(entry.Name(), "cgroup"))
	if err != nil {
		return "", nil
	}
	defer cgroup.Close()

	var cgroupData bytes.Buffer
	_, err = io.Copy(&cgroupData, cgroup)
	if err != nil {
		return "", nil
	}

	uid, _, err := nd.GetPodUIDAndContainerID(cgroupData)
	if err != nil {
		return "", err
	}

	if filter != uid {
		return "", nil
	}

	log.Debugf("found pod to netns: %s %d", uid, inode)

	return netnsName, nil
}
