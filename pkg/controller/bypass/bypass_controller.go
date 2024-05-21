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

package bypass

import (
	"bytes"
	"context"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"path"
	"strings"
	"syscall"
	"time"

	netns "github.com/containernetworking/plugins/pkg/ns"
	nd "istio.io/istio/cni/pkg/nodeagent"
	"istio.io/istio/pkg/util/sets"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	log = logger.NewLoggerField("bypass")
	FS  embed.FS
)

const (
	DefaultInformerSyncPeriod = 30 * time.Second
	LabelSelectorBypass       = "kmesh.net/bypass=enabled"
)

func StartByPassController(client kubernetes.Interface) error {
	stopChan := make(chan struct{})
	nodeName := os.Getenv("NODE_NAME")

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, DefaultInformerSyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
			options.LabelSelector = LabelSelectorBypass
		}))

	informerFactory.Start(wait.NeverStop)
	informerFactory.WaitForCacheSync(wait.NeverStop)

	podInformer := informerFactory.Core().V1().Pods().Informer()

	if _, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}

			log.Infof("%s/%s: enable bypass control", pod.GetNamespace(), pod.GetName())
			enableSidecar, _ := checkSidecar(client, pod)
			enableKmesh := checkKmesh(pod)
			if !enableSidecar && !enableKmesh {
				log.Info("do not need process, pod is not managed by sidecar or kmesh")
				return
			}

			nspath, _ := getnspath(pod)

			if enableSidecar {
				if err := addIptables(nspath); err != nil {
					log.Errorf("failed to add iptables rules for %s: %v", nspath, err)
					return
				}
			}
			if enableKmesh {
				if err := handleKmeshBypass(nspath, 931); err != nil {
					log.Errorf("failed to bypass kmesh control")
					return
				}
			}
		},
		DeleteFunc: func(obj interface{}) {
			if _, ok := obj.(cache.DeletedFinalStateUnknown); ok {
				return
			}
			pod, ok := obj.(*corev1.Pod)
			if !ok {
				log.Errorf("expected *corev1.Pod but got %T", obj)
				return
			}

			if isPodBeingDeleted(pod) {
				log.Debugf("%s/%s: Pod is being deleted, skipping further processing", pod.GetNamespace(), pod.GetName())
				return
			}

			log.Infof("%s/%s: disable bypass control", pod.GetNamespace(), pod.GetName())
			enableSidecar, _ := checkSidecar(client, pod)
			enableKmesh := checkKmesh(pod)

			if enableSidecar {
				nspath, _ := getnspath(pod)
				if err := deleteIptables(nspath); err != nil {
					log.Errorf("failed to add iptables rules for %s: %v", nspath, err)
					return
				}
			}
			if enableKmesh {
				nspath, _ := getnspath(pod)
				if err := handleKmeshBypass(nspath, 932); err != nil {
					log.Errorf("failed to enable kmesh control")
					return
				}
			}
		},
	}); err != nil {
		return fmt.Errorf("error adding event handler to podInformer: %v", err)
	}

	go podInformer.Run(stopChan)

	return nil
}

func handleKmeshBypass(ns string, port int) error {
	execFunc := func(netns.NetNS) error {
		/*
		 * Attempt to connect to a special IP address. The
		 * connection triggers the cgroup/connect4 ebpf
		 * program and records the netns cookie information
		 * of the current connection. The cookie can be used
		 * to determine whether the netns is been bypass.
		 * 0.0.0.1:<port> is "cipher key" for cgroup/connect4
		 * ebpf program.
		 */
		simip := net.ParseIP("0.0.0.1")
		sockfd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
		if err != nil {
			return err
		}
		if err = syscall.SetNonblock(sockfd, true); err != nil {
			return err
		}
		err = syscall.Connect(sockfd, &syscall.SockaddrInet4{
			Port: port,
			Addr: [4]byte(simip.To4()),
		})
		if err == nil {
			return err
		}
		errno, ok := err.(syscall.Errno)
		if ok && errno == 115 { // -EINPROGRESS, Operation now in progress
			return nil
		}
		return err
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		err = fmt.Errorf("enter ns path :%v, run execFunc failed: %v", ns, err)
		return err
	}
	return nil
}

func isPodBeingDeleted(pod *corev1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

func addIptables(ns string) error {
	iptArgs := [][]string{
		{"-t", "nat", "-I", "PREROUTING", "1", "-j", "RETURN"},
		{"-t", "nat", "-I", "OUTPUT", "1", "-j", "RETURN"},
	}

	execFunc := func(netns.NetNS) error {
		log.Infof("Running add iptables rule in namespace:%s", ns)
		for _, args := range iptArgs {
			if err := utils.Execute("iptables", args); err != nil {
				return fmt.Errorf("failed to exec command: iptables %v\", err: %v", args, err)
			}
		}
		return nil
	}
	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		return fmt.Errorf("enter namespace path: %v, run command failed: %v", ns, err)
	}
	return nil
}

func deleteIptables(ns string) error {
	iptArgs := [][]string{
		{"-t", "nat", "-D", "PREROUTING", "-j", "RETURN"},
		{"-t", "nat", "-D", "OUTPUT", "-j", "RETURN"},
	}

	execFunc := func(netns.NetNS) error {
		log.Infof("Running delete iptables rule in namespace:%s", ns)
		for _, args := range iptArgs {
			if err := utils.Execute("iptables", args); err != nil {
				err = fmt.Errorf("failed to exec command: iptables %v\", err: %v", args, err)
				log.Error(err)
				return err
			}
		}
		return nil
	}

	if err := netns.WithNetNSPath(ns, execFunc); err != nil {
		return fmt.Errorf("enter namespace path: %v, run command failed: %v", ns, err)
	}
	return nil
}

func checkSidecar(client kubernetes.Interface, pod *corev1.Pod) (bool, error) {
	namespace, err := client.CoreV1().Namespaces().Get(context.TODO(), pod.Namespace, metav1.GetOptions{})
	if err != nil {
		return false, err
	}

	if value, ok := namespace.Labels["istio-injection"]; ok && value == "enabled" {
		return true, nil
	}

	if _, ok := pod.Annotations["sidecar.istio.io/inject"]; ok {
		return true, nil
	}

	return false, nil
}

func checkKmesh(pod *corev1.Pod) bool {
	annotations := pod.Annotations
	if annotations != nil {
		if value, ok := annotations["kmesh.net/redirection"]; ok && value == "enabled" {
			return true
		}
	}
	return false
}

func getnspath(pod *corev1.Pod) (string, error) {
	res, err := FindNetnsForPod(pod)
	if err != nil {
		return "", err
	}
	res = path.Join("/proc", res)
	return res, nil
}

func BuiltinOrDir(dir string) fs.FS {
	if dir == "" {
		return FS
	}
	return os.DirFS(dir)
}

func FindNetnsForPod(pod *corev1.Pod) (string, error) {
	netnsObserved := sets.New[uint64]()
	fd := BuiltinOrDir("/proc")

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

// copied from istio/cni/pkg/nodeagent/podcgroupns.go
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
