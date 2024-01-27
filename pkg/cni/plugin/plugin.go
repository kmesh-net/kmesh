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

package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	log               = logger.NewLoggerFieldWithoutStdout("plugin/cniplugin")
	ENABLE_KMESH_MARK = "0x1000"
)

// Config is whatever you expect your configuration json to be. This is whatever
// is passed in on stdin. Your plugin may wish to expose its functionality via
// runtime args, see CONVENTIONS.md in the CNI spec.
type cniConf struct {
	types.NetConf

	// Add plugin-specific flags here
	KubeConfig string `json:"kubeconfig,omitempty"`
}

/*
 * K8sArgs parameter is used to transfer the k8s information transferred
 * when the cni plugin is invoked.
 * The field names need to match exact keys in kubelet args for unmarshalling
 */
type k8sArgs struct {
	types.CommonArgs
	K8S_POD_NAME      types.UnmarshallableString
	K8S_POD_NAMESPACE types.UnmarshallableString
}

func parseSkelArgs(args *skel.CmdArgs) (*cniConf, *k8sArgs, *cniv1.Result, error) {
	cniConf := cniConf{}
	if err := json.Unmarshal(args.StdinData, &cniConf); err != nil {
		log.Errorf("failed to unmarshal json: %v", err)
		return nil, nil, nil, err
	}

	result, err := getPrevCniResult(&cniConf)
	if err != nil {
		log.Error("failed to get cni result")
		return nil, nil, nil, err
	}

	k8sCommonArgs := k8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sCommonArgs); err != nil {
		log.Errorf("failed to load k8s args: %v", err)
		return nil, nil, result, err
	}
	return &cniConf, &k8sCommonArgs, result, nil
}

// checkKmesh checks whether we should enable kmesh for the given pod
func checkKmesh(clientSet *kubernetes.Clientset, pod *v1.Pod) (bool, error) {
	namespace, err := clientSet.CoreV1().Namespaces().Get(context.TODO(), pod.Namespace, metav1.GetOptions{})
	if err != nil {
		return false, err
	}
	var enableSidecar bool
	injectLabel := namespace.Labels["istio-injection"]
	if injectLabel == "enabled" {
		enableSidecar = true
	}
	// According to istio, it support per pod config.
	injValue := pod.Annotations["sidecar.istio.io/inject"]
	if v, ok := pod.Labels["sidecar.istio.io/inject"]; ok {
		injValue = v
	}
	if inject, err := strconv.ParseBool(injValue); err == nil {
		enableSidecar = inject
	}

	// If sidecar inject enabled, kmesh do not take charge of it.
	if enableSidecar {
		return false, nil
	}

	mode := namespace.Labels["istio.io/dataplane-mode"]
	if strings.EqualFold(mode, "Kmesh") {
		return true, nil
	}

	return false, nil
}

func enableKmeshControl(clientSet *kubernetes.Clientset, pod *v1.Pod) error {
	classIDPathPrefix := "/sys/fs/cgroup/net_cls/kubepods"

	qosClass := strings.ToLower(string(pod.Status.QOSClass))
	podUID := "pod" + pod.UID
	classidFile := "net_cls.classid"
	netClsPath := path.Join(classIDPathPrefix, string(qosClass), string(podUID), classidFile)

	file, err := os.OpenFile(netClsPath, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		err = fmt.Errorf("failed to open net cls path: %v, %v", netClsPath, err)
		log.Error(err)
		return err
	}
	defer file.Close()
	if err := utils.ExecuteWithRedirect("echo", []string{ENABLE_KMESH_MARK}, file); err != nil {
		err = fmt.Errorf("failed to exec cmd with redirect: %v", err)
		log.Error(err)
		return err
	}

	if _, err = clientSet.CoreV1().Pods(pod.Namespace).Patch(
		context.Background(),
		pod.Name,
		k8stypes.MergePatchType,
		annotationPatch,
		metav1.PatchOptions{},
	); err != nil {
		log.Errorf("failed to annotate kmesh redirection: %v", err)
	}

	return nil
}

const KmeshRedirection = "kmesh.net/redirection"

var annotationPatch = []byte(fmt.Sprintf(
	`{"metadata":{"annotations":{"%s":"%s"}}}`,
	KmeshRedirection,
	"enabled",
))

func getPrevCniResult(conf *cniConf) (*cniv1.Result, error) {
	var err error
	if conf.RawPrevResult == nil {
		err = fmt.Errorf("kmesh-cni can not use standalone")
		log.Error(err)
		return nil, err
	}

	prevResultBytes, err := json.Marshal(conf.RawPrevResult)
	if err != nil {
		log.Errorf("failed to serialize prev cni result: %v", err)
		return nil, err
	}
	res, err := version.NewResult(conf.CNIVersion, prevResultBytes)
	if err != nil {
		log.Errorf("failed to parse prev result: %v", err)
		return nil, err
	}
	cniv1PrevResult, err := cniv1.NewResultFromResult(res)
	if err != nil {
		log.Errorf("failed to convert result to version %s: %v", cniv1.ImplementedSpecVersion, err)
		return nil, err
	}
	return cniv1PrevResult, nil
}

/* if cmaadd failed, then we cannot return failed, do nothing and print pre result */
func CmdAdd(args *skel.CmdArgs) error {
	var err error
	cniConf, k8sConf, preResult, err := parseSkelArgs(args)
	if err != nil {
		log.Error("failed to parse config")
		if preResult == nil {
			return err
		}
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	podName := string(k8sConf.K8S_POD_NAME)
	podNamespace := string(k8sConf.K8S_POD_NAMESPACE)
	if podName == "" || podNamespace == "" {
		log.Debug("Not a kubernetes pod")
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	clientSet, err := utils.CreateK8sClientSet(cniConf.KubeConfig)
	if err != nil {
		err = fmt.Errorf("failed to get k8s client: %v", err)
		log.Error(err)
		return err
	}

	pod, err := clientSet.CoreV1().Pods(podNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get pod: %v", err)
		return err
	}

	enableKmesh, err := checkKmesh(clientSet, pod)
	if err != nil {
		log.Errorf("failed to check enable kmesh information: %v", err)
		return err
	}

	if !enableKmesh {
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	if err := enableKmeshControl(clientSet, pod); err != nil {
		log.Error("failed to enable kmesh control")
		return err
	}

	return types.PrintResult(preResult, cniConf.CNIVersion)
}

func CmdCheck(args *skel.CmdArgs) (err error) {
	return nil
}

func CmdDelete(args *skel.CmdArgs) error {
	return nil
}
