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
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"strconv"
	"strings"

	netns "github.com/containernetworking/plugins/pkg/ns"

	"github.com/cilium/ebpf"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniv1 "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/vishvananda/netlink"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8stypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/utils"
	"kmesh.net/kmesh/pkg/utils/hash"
)

var (
	log                        = logger.NewLoggerFieldWithoutStdout("plugin/cniplugin")
	ENABLE_KMESH_MARK          = "0x1000"
	XDP_PROG_NAME              = "xdp_shutdown"
	ENABLED_KMESH_MAP_PIN_PATH = "/sys/fs/bpf/bpf_kmesh_workload/map/map_of_kmesh_manager"
)

// Config is whatever you expect your configuration json to be. This is whatever
// is passed in on stdin. Your plugin may wish to expose its functionality via
// runtime args, see CONVENTIONS.md in the CNI spec.
type cniConf struct {
	types.NetConf

	// Add plugin-specific flags here
	KubeConfig string `json:"kubeconfig,omitempty"`
}

type kmeshManagerKey struct {
	ContainerID uint64
	IpAddress   uint32
	Index       uint32
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
func checkKmesh(client kubernetes.Interface, pod *v1.Pod) (bool, error) {
	namespace, err := client.CoreV1().Namespaces().Get(context.TODO(), pod.Namespace, metav1.GetOptions{})
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

func kmeshCtlByClassid(client kubernetes.Interface, pod *v1.Pod) error {
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

	if _, err = client.CoreV1().Pods(pod.Namespace).Patch(
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

/*
 * there have a containerID and its hash is 64334212, it have 3 ip address in pod
 * there have 7 record in thie map.
 *      |containerID        |ip     |index      |||value        |
 * 1.   |64334214           |0      |0          |||3            |
 * 2.   |64334214           |0      |1          |||ip1          |
 * 3.   |64334214           |0      |2          |||ip2          |
 * 4.   |64334214           |0      |3          |||ip3          |
 * 5.   |0                  |ip1    |0          |||0            |
 * 6.   |0                  |ip2    |0          |||0            |
 * 7.   |0                  |ip3    |0          |||0            |
 *
 * Why design it that way?
 * We need a way to mark in the cni whether the current ip is managed by Kmesh.
 * The cni inserts the ip address into the map when the pod is created and removes the ip
 * address from the map when the pod is destroyed.
 * However, according to the cni guide, when deleting the data, only the CONTAINER and IFNAME
 * (https://github.com/containernetworking/cni.dev/blob/main/content/docs/spec.md#del-remove-container-from-network-or-un-apply-modifications)
 * must be transferred. The IP address is not transferred in the cni. Therefore, the
 * containerID and IP address must be bound and stored in the map for subsequent deletion.
 */

func kmeshCtlByIP(targetmap *ebpf.Map, preResult *cniv1.Result, containerID string) error {
	var keyIP kmeshManagerKey
	var keyContainer kmeshManagerKey
	var value uint32 = 0
	var totalNum uint32
	var err error

	keyContainer.ContainerID = hash.Sum64String(containerID)

	for _, allocIP := range preResult.IPs {
		keyIP.IpAddress = binary.LittleEndian.Uint32(allocIP.Address.IP.To4())
		keyContainer.Index = totalNum + 1

		if err = targetmap.Update(&keyContainer, &keyIP.IpAddress, ebpf.UpdateAny); err != nil {
			log.Errorf("failed to record container :%v: %v", keyContainer.ContainerID, err)
			// Try to insert the rest of the ip
			continue
		}

		if err = targetmap.Update(&keyIP, &value, ebpf.UpdateAny); err != nil {
			log.Errorf("failed to record ip %+v: %v", keyIP, err)
			targetmap.Delete(&keyContainer) // nolint: errcheck
			continue
		}
		totalNum++
	}
	keyContainer.Index = 0
	value = totalNum
	if err = targetmap.Update(&keyContainer, &value, ebpf.UpdateAny); err != nil {
		log.Errorf("failed to record container total ip num %+v: %v", keyContainer, err)
		return err
	}
	return nil
}

func kmeshDisCtlByIP(targetmap *ebpf.Map, containerID string) {
	var totalNum uint32
	var keyContainer kmeshManagerKey
	var keyIP kmeshManagerKey
	var index uint32

	keyContainer.ContainerID = hash.Sum64String(containerID)
	if err := targetmap.Lookup(&keyContainer, &totalNum); err != nil {
		// The cmddelete command is invoked more than once.
		// If the command is invoked multiple times, the floolwing error information is desplayed
		log.Errorf("can not found container info in kmesh manager map")
		return
	}

	for index = 0; index < totalNum; index++ {
		keyContainer.Index = index + 1
		if err := targetmap.Lookup(&keyContainer, &keyIP.IpAddress); err != nil {
			log.Errorf("can not found a valid ip, info:%+v", keyContainer)
			continue
		}
		targetmap.Delete(&keyIP)        // nolint: errcheck
		targetmap.Delete(&keyContainer) // nolint: errcheck
	}
	keyContainer.Index = 0
	targetmap.Delete(&keyContainer) // nolint: errcheck
}

func enableKmeshControl(client kubernetes.Interface, pod *v1.Pod, preResult *cniv1.Result, containerID string) error {
	if err := kmeshCtlByClassid(client, pod); err != nil {
		return err
	}

	recordmap, err := ebpf.LoadPinnedMap(ENABLED_KMESH_MAP_PIN_PATH, nil)
	if err != nil {
		log.Errorf("failed to get a valid kmesh_enabled map")
		return err
	}

	if err = kmeshCtlByIP(recordmap, preResult, containerID); err != nil {
		kmeshDisCtlByIP(recordmap, containerID)
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

func enableXdpAuth(ifname string) error {
	var (
		err  error
		xdp  *ebpf.Program
		link netlink.Link
	)

	if xdp, err = utils.GetProgramByName(XDP_PROG_NAME); err != nil {
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

	enableKmesh, err := checkKmesh(client, pod)
	if err != nil {
		log.Errorf("failed to check enable kmesh information: %v", err)
		return err
	}

	if !enableKmesh {
		return types.PrintResult(preResult, cniConf.CNIVersion)
	}

	if err := enableKmeshControl(client, pod, preResult, args.ContainerID); err != nil {
		log.Error("failed to enable kmesh control")
		return err
	}

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

	return types.PrintResult(preResult, cniConf.CNIVersion)
}

func CmdCheck(args *skel.CmdArgs) (err error) {
	return nil
}

func CmdDelete(args *skel.CmdArgs) error {
	// clean
	recordmap, err := ebpf.LoadPinnedMap(ENABLED_KMESH_MAP_PIN_PATH, nil)
	if err != nil {
		log.Errorf("failed to get a valid kmesh_enabled map")
		// cmd delete must be return nil
		return nil
	}
	kmeshDisCtlByIP(recordmap, args.ContainerID)
	return nil
}
