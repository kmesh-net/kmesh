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

package plugin

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	netns "github.com/containernetworking/plugins/pkg/ns"
	"github.com/vishvananda/netlink"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
)

var (
	log = logger.NewLoggerFieldWithoutStdout("plugin/cniplugin")
)

// cniConf is whatever you expect your configuration json to be. This is whatever
// is passed in on stdin. Your plugin may wish to expose its functionality via
// runtime args, see CONVENTIONS.md in the CNI spec.
type cniConf struct {
	types.NetConf

	// Add plugin-specific flags here
	KubeConfig string `json:"kubeconfig,omitempty"`
	Mode       string `json:"mode,omitempty"`
}

// K8sArgs parameter is used to transfer the k8s information transferred
// when the cni plugin is invoked.
// The field names need to match exact keys in kubelet args for unmarshalling
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

func enableXdpAuth(ifname string) error {
	var (
		err  error
		xdp  *ebpf.Program
		link netlink.Link
	)

	if xdp, err = utils.GetProgramByName(constants.XDP_PROG_NAME); err != nil {
		return err
	}

	if link, err = netlink.LinkByName(ifname); err != nil {
		return err
	}

	if err = netlink.LinkSetXdpFd(link, xdp.FD()); err != nil {
		return err
	}

	return nil
}

// if cmdadd failed, then we cannot return failed, do nothing and print pre result
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

	client, err := utils.CreateK8sClientSet(cniConf.KubeConfig)
	if err != nil {
		err = fmt.Errorf("failed to get k8s client: %v", err)
		log.Error(err)
		return err
	}

	pod, err := client.CoreV1().Pods(podNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
	if err != nil {
		err = fmt.Errorf("failed to get pod: %v", err)
		return err
	}

	namespace, err := client.CoreV1().Namespaces().Get(context.TODO(), pod.Namespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %v", pod.Namespace, err)
	}

	enableKmesh := utils.ShouldEnroll(pod, namespace)

	if !enableKmesh {
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	if err := utils.HandleKmeshManage(args.Netns, true); err != nil {
		log.Errorf("failed to enable kmesh control, err is %v", err)
		return err
	}

	if err := utils.PatchKmeshRedirectAnnotation(client, pod); err != nil {
		log.Errorf("failed to annotate kmesh redirection, err is %v", err)
	}

	if cniConf.Mode == constants.WorkloadMode {
		enableXDPFunc := func(netns.NetNS) error {
			if err := enableXdpAuth(args.IfName); err != nil {
				err = fmt.Errorf("failed to set xdp to dev %v, err is %v", args.IfName, err)
				return err
			}
			return nil
		}

		if err := netns.WithNetNSPath(string(args.Netns), enableXDPFunc); err != nil {
			log.Error(err)
			return err
		}
	}

	return types.PrintResult(preResult, cniConf.CNIVersion)
}

func CmdCheck(args *skel.CmdArgs) (err error) {
	return nil
}

func CmdDelete(args *skel.CmdArgs) error {
	// clean
	if err := utils.HandleKmeshManage(args.Netns, false); err != nil {
		log.Errorf("failed to disable Kmesh control, err: %v", err)
	}

	// cmd delete must be return nil
	return nil
}
