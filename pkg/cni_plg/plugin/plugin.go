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
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	netns "github.com/containernetworking/plugins/pkg/ns"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"oncn.io/mesh/pkg/logger"
	"oncn.io/mesh/pkg/utils"
)

var (
	log               = logger.NewLoggerFieldWithoutStdout("plugin/cniplugin")
	ENABLE_KMESH_MARK = "0x1000"
)

type cniConf struct {
	types.NetConf
	PrevResult *map[string]interface{} `json:"prevResult"`
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

func checkK8sNSLabel(podNamespace string) (bool, bool, error) {
	var enableKmesh bool = false
	var enableSidecar bool = false

	clientSet, err := utils.GetK8sclient()
	if err != nil {
		err = fmt.Errorf("failed to get k8s client: %v", err)
		log.Error(err)
		return enableKmesh, enableSidecar, err
	}
	namespace, err := clientSet.CoreV1().Namespaces().Get(context.TODO(), podNamespace, metav1.GetOptions{})
	if err != nil {
		log.Error(err)
		return enableKmesh, enableSidecar, err
	}

	labelValue, ok := namespace.Labels["istio.io/dataplane-mode"]

	if ok && labelValue == "Kmesh" {
		enableKmesh = true
	}

	labelValue, ok = namespace.Labels["istio-injection"]

	if ok && labelValue == "enabled" {
		enableSidecar = true
	}

	return enableKmesh, enableSidecar, nil
}

func enableKmeshControl(podName, k8sNs string) error {
	clientSet, err := utils.GetK8sclient()
	if err != nil {
		err = fmt.Errorf("failed to get k8s client: %v", err)
		log.Error(err)
		return err
	}

	classIDPathPrefix := "/sys/fs/cgroup/net_cls/kubepods"

	pod, err := clientSet.CoreV1().Pods(k8sNs).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get pod info: %v", err)
		log.Error(err)
		return err
	}

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
	return nil
}

func bypassSidecar(iptFlag bool, ns string) error {
	if !iptFlag {
		log.Debugf("don't need inject iptables rule, skip")
		return nil
	}
	iptArgs := [][]string{
		{"-t", "nat", "-I", "PREROUTING", "1", "-j", "RETURN"},
		{"-t", "nat", "-I", "OUTPUT", "1", "-j", "RETURN"},
	}

	execFunc := func(netns.NetNS) error {
		log.Debugf("Running iptables rule in namespace:%s", ns)
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
		err = fmt.Errorf("enter ns path: %v, run command failed: %v", ns, err)
		return err
	}
	return nil
}

func getPrevCniResult(conf *cniConf) (*cniv1.Result, error) {
	var err error
	if conf.PrevResult == nil {
		err = fmt.Errorf("kmesh-cniplugin can not use standalone")
		log.Error(err)
		return nil, err
	}

	prevResultBytes, err := json.Marshal(conf.PrevResult)
	if err != nil {
		log.Errorf("failed to get prev cni result: %v", err)
		return nil, err
	}
	prevResult, err := version.NewResult(conf.CNIVersion, prevResultBytes)
	if err != nil {
		log.Errorf("failed to parse prev result: %v", err)
		return nil, err
	}
	cniv1PrevResult, err := cniv1.NewResultFromResult(prevResult)
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

	enableKmesh, enableSidecar, err := checkK8sNSLabel(string(k8sConf.K8S_POD_NAMESPACE))
	if err != nil {
		log.Error("failed to check enable kmesh information")
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	if !enableKmesh {
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	if err := enableKmeshControl(string(k8sConf.K8S_POD_NAME), string(k8sConf.K8S_POD_NAMESPACE)); err != nil {
		log.Error("failed to enable kmesh control")
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	if !enableSidecar {
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	if err := bypassSidecar(enableSidecar, string(args.Netns)); err != nil {
		log.Errorf("failed to inject iptables rule: %v", err)
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	return types.PrintResult(preResult, cniConf.CNIVersion)
}

func CmdCheck(args *skel.CmdArgs) (err error) {
	return nil
}

func CmdDelete(args *skel.CmdArgs) error {
	return nil
}
