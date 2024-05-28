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

package kmeshmanage

import (
	"context"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	netns "github.com/containernetworking/plugins/pkg/ns"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"

	ns "kmesh.net/kmesh/pkg/controller/netns"
	"kmesh.net/kmesh/pkg/logger"
)

var (
	log                = logger.NewLoggerField("kmesh_manage")
	annotationDelPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":null}}}`,
		KmeshAnnotation,
	))
	annotationAddPatch = []byte(fmt.Sprintf(
		`{"metadata":{"annotations":{"%s":"%s"}}}`,
		KmeshAnnotation,
		"enabled",
	))
)

const (
	DefaultInformerSyncPeriod = 30 * time.Second
	SpecialIpForKmesh         = "0.0.0.1"
	EnableKmeshPort           = 929
	DisableKmeshPort          = 930
	LabelSelectorKmesh        = "istio.io/dataplane-mode=Kmesh"
	KmeshAnnotation           = "kmesh.net/redirection"
)

func NewKmeshManageController(client kubernetes.Interface) error {
	stopChan := make(chan struct{})
	nodeName := os.Getenv("NODE_NAME")

	informerFactory := informers.NewSharedInformerFactoryWithOptions(client, DefaultInformerSyncPeriod,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
			options.LabelSelector = LabelSelectorKmesh
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

			log.Infof("%s/%s: Kmesh manage pod:", pod.GetNamespace(), pod.GetName())

			nspath, _ := ns.GetNSpath(pod)

			if err := handleKmeshManage(nspath, true); err != nil {
				log.Errorf("failed to enable Kmesh manage")
				return
			}
			if err := patchKmeshAnnotation(client, pod, true); err != nil {
				log.Errorf("failed to add Kmesh annotation, err is %v", err)
				return
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

			log.Infof("%s/%s: disable Kmesh manage", pod.GetNamespace(), pod.GetName())

			nspath, _ := ns.GetNSpath(pod)
			if err := handleKmeshManage(nspath, false); err != nil {
				log.Errorf("failed to disable Kmesh manage")
				return
			}

			if err := patchKmeshAnnotation(client, pod, false); err != nil {
				log.Errorf("failed to add Kmesh annotation, err is %v", err)
				return
			}
		},
	}); err != nil {
		return fmt.Errorf("failed to add event handler to podInformer: %v", err)
	}

	go podInformer.Run(stopChan)

	return nil
}

func isPodBeingDeleted(pod *corev1.Pod) bool {
	return pod.ObjectMeta.DeletionTimestamp != nil
}

func patchKmeshAnnotation(client kubernetes.Interface, pod *corev1.Pod, op bool) error {
	annotationPatch := annotationAddPatch
	if !op {
		annotationPatch = annotationDelPatch
	}
	_, err := client.CoreV1().Pods(pod.Namespace).Patch(
		context.Background(),
		pod.Name,
		k8stypes.MergePatchType,
		annotationPatch,
		metav1.PatchOptions{},
	)
	return err
}

func handleKmeshManage(ns string, op bool) error {
	execFunc := func(netns.NetNS) error {
		/*
		 * This function is used to process pods that are marked
		 * or deleted with the bypass label on the current node.
		 * Attempt to connect to a special IP address. The
		 * connection triggers the cgroup/connect4 ebpf
		 * program and records the netns cookie information
		 * of the current connection. The cookie can be used
		 * to determine whether the pod is been bypass.
		 * 0.0.0.1:<port> is "cipher key" for cgroup/connect4
		 * ebpf program. 929/930 is the specific port handled by
		 * daemon to enable/disable kmesh manage
		 */
		simip := net.ParseIP(SpecialIpForKmesh)
		port := EnableKmeshPort
		if !op {
			port = DisableKmeshPort
		}
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
		if ok && errno == syscall.EINPROGRESS { // Operation now in progress
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
