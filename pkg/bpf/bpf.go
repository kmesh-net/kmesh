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

// #cgo pkg-config: api-v2-c
// #include "deserialization_to_bpf_map.h"
import "C"
import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/ads"
	"kmesh.net/kmesh/pkg/bpf/factory"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/workload"
	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/kube"
	"kmesh.net/kmesh/pkg/logger"
	"kmesh.net/kmesh/pkg/nets"
	"kmesh.net/kmesh/pkg/version"
)

var (
	log  = logger.NewLoggerScope("bpf")
	hash = fnv.New32a()
)

type BpfLoader struct {
	config *options.BpfConfig

	obj         *ads.BpfAds
	workloadObj *workload.BpfWorkload
	factory.KmeshBpfConfig
	versionMap *ebpf.Map
}

func NewBpfLoader(config *options.BpfConfig) *BpfLoader {
	return &BpfLoader{
		config:     config,
		versionMap: NewVersionMap(config),
	}
}

func StartMda() error {
	cmd := exec.Command("mdacore", "enable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(strings.Replace(string(output), "\n", " ", -1))
		return err
	}

	log.Info(strings.Replace(string(output), "\n", " ", -1))
	return nil
}

func (l *BpfLoader) Start() error {
	var err error
	if l.config.KernelNativeEnabled() {
		if l.obj, err = ads.NewBpfAds(l.config); err != nil {
			return err
		}
		if err = l.obj.Start(); err != nil {
			return err
		}
		l.KmeshBpfConfig = l.obj.GetBpfConfigVariable()
	} else if l.config.DualEngineEnabled() {
		if l.workloadObj, err = workload.NewBpfWorkload(l.config); err != nil {
			return err
		}
		if err = l.workloadObj.Start(); err != nil {
			return err
		}
		l.KmeshBpfConfig = l.workloadObj.GetBpfConfigVariable()
		// TODO: set bpf prog option in kernel native node
		l.setBpfProgOptions()
	}

	// TODO: move start mds out of bpf loader
	if l.config.EnableMda {
		if err = StartMda(); err != nil {
			return err
		}
	}

	if restart.GetStartType() == restart.Restart {
		log.Infof("bpf load from last pinPath")
	}
	return nil
}

func (l *BpfLoader) GetBpfKmesh() *ads.BpfAds {
	if l == nil {
		return nil
	}
	return l.obj
}

func (l *BpfLoader) GetBpfWorkload() *workload.BpfWorkload {
	if l == nil {
		return nil
	}
	return l.workloadObj
}

func StopMda() error {
	cmd := exec.Command("mdacore", "disable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error(strings.Replace(string(output), "\n", " ", -1))
		return err
	}

	log.Info(strings.Replace(string(output), "\n", " ", -1))
	return nil
}

func (l *BpfLoader) Stop() {
	var err error
	C.deserial_uninit()
	if restart.GetExitType() == restart.Restart {
		return
	}

	closeMap(l.versionMap)
	if l.config.KernelNativeEnabled() {
		if err = l.obj.Stop(); err != nil {
			CleanupBpfMap()
			log.Errorf("failed stop bpf, err: %v", err)
			return
		}
	} else if l.config.DualEngineEnabled() {
		if err = l.workloadObj.Stop(); err != nil {
			CleanupBpfMap()
			log.Errorf("failed stop bpf workload, err: %v", err)
			return
		}
	}

	if l.config.EnableMda {
		if err = StopMda(); err != nil {
			log.Errorf("failed disable mda when stop kmesh, err:%s", err)
		}
	}

	CleanupBpfMap()
}

func NewVersionMap(config *options.BpfConfig) *ebpf.Map {
	var versionPath string
	var kmBpfPath string
	var versionMap *ebpf.Map
	if config.KernelNativeEnabled() {
		versionPath = filepath.Join(config.BpfFsPath, constants.VersionPath)
		kmBpfPath = filepath.Join(config.BpfFsPath, constants.KmKernelNativeBpfPath)
	} else if config.DualEngineEnabled() {
		versionPath = filepath.Join(config.BpfFsPath, constants.WorkloadVersionPath)
		kmBpfPath = filepath.Join(config.BpfFsPath, constants.KmDualEngineBpfPath)
	}

	versionMapPinPath := filepath.Join(versionPath, "kmesh_version")
	_, err := os.Stat(versionPath)
	if err == nil {
		versionMap = recoverVersionMap(versionMapPinPath)
		if versionMap != nil {
			restart.SetStartStatus(versionMap)
		}
	}

	switch restart.GetStartType() {
	case restart.Restart:
		return versionMap
	case restart.Update:
		// TODO : update mode has not been fully developed and is currently consistent with normal mode
		log.Warnf("Update mode support is under development, Will be started in Normal mode.")
	default:
	}

	// Make sure the directory about to use is clean
	err = os.RemoveAll(kmBpfPath)
	if err != nil {
		log.Errorf("Clean bpf maps and progs failed, err is:%v", err)
		return nil
	}

	mapSpec := &ebpf.MapSpec{
		Name:       "kmesh_version",
		Type:       ebpf.Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	m, err := ebpf.NewMap(mapSpec)
	if err != nil {
		log.Errorf("Create kmesh_version map failed, err is %v", err)
		return nil
	}

	if err := os.MkdirAll(versionPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		log.Errorf("mkdir failed %v", err)
		return nil
	}

	err = m.Pin(versionMapPinPath)
	if err != nil {
		log.Errorf("kmesh_version pin failed: %v", err)
		return nil
	}

	storeVersionInfo(m)
	log.Infof("kmesh start with Normal")
	restart.SetStartType(restart.Normal)
	return m
}

func storeVersionInfo(versionMap *ebpf.Map) {
	key := uint32(0)
	var value uint32
	hash.Reset()
	hash.Write([]byte(version.Get().GitVersion))
	value = hash.Sum32()
	if err := versionMap.Put(&key, &value); err != nil {
		log.Errorf("Add Version Map failed, err is %v", err)
	}
}

func recoverVersionMap(pinPath string) *ebpf.Map {
	opts := &ebpf.LoadPinOptions{
		ReadOnly:  false,
		WriteOnly: false,
		Flags:     0,
	}

	versionMap, err := ebpf.LoadPinnedMap(pinPath, opts)
	if err != nil {
		log.Infof("kmesh version map load failed: %v, start normally", err)

		return nil
	}
	log.Debugf("recoverVersionMap success")

	return versionMap
}

func (l *BpfLoader) setBpfProgOptions() {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		log.Error("skip kubelet probe failed: node name empty")
		return
	}

	clientSet, err := kube.CreateKubeClient("")
	if err != nil {
		log.Errorf("get kubernetest client for getting node IP error: %v", err)
		return
	}

	node, err := clientSet.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		log.Errorf("failed to get node: %v", err)
		return
	}

	// pass node ip and pod gateway to skip processing of kubelet access traffic.
	nodeIP := getNodeIPAddress(node)
	gateway := getNodePodSubGateway(node)

	// Kmesh reboot updates only the nodeIP and pod sub gateway
	if restart.GetStartType() == restart.Normal {
		if err := l.NodeIP.Set(nodeIP); err != nil {
			log.Error("set NodeIP failed ", err)
			return
		}
		if err := l.PodGateway.Set(gateway); err != nil {
			log.Error("set PodGateway failed ", err)
			return
		}
		if err := l.AuthzOffload.Set(constants.ENABLED); err != nil {
			log.Error("set AuthzOffload failed ", err)
			return
		}
		if err := l.EnableMonitoring.Set(constants.ENABLED); err != nil {
			log.Error("set EnableMonitoring failed ", err)
			return
		}
	}
}

func getNodeIPAddress(node *corev1.Node) [16]byte {
	var nodeIPStr string
	nodeAddresses := node.Status.Addresses
	for _, address := range nodeAddresses {
		if address.Type == corev1.NodeInternalIP {
			nodeIPStr = address.Address
		}
	}

	nodeIP, err := netip.ParseAddr(nodeIPStr)
	if err != nil {
		log.Errorf("failed to parse node ip: %v", err)
		return [16]byte{}
	}

	return nodeIP.As16()
}

func getNodePodSubGateway(node *corev1.Node) [16]byte {
	podCIDR := node.Spec.PodCIDR
	if podCIDR == "" {
		return [16]byte{0}
	}

	_, subNet, err := net.ParseCIDR(podCIDR)
	if err != nil {
		log.Errorf("failed to resolve ip from podCIDR: %v", err)
		return [16]byte{0}
	}
	podGateway := [16]byte{0}
	nets.CopyIpByteFromSlice(&podGateway, subNet.IP.To16())
	podGateway[15] = podGateway[15] + 1
	return podGateway
}

func (l *BpfLoader) UpdateKmeshConfigMap(config factory.GlobalBpfConfig) error {
	if err := l.UpdateBpfLogLevel(config.BpfLogLevel); err != nil {
		return err
	}

	if err := l.UpdateNodeIP(config.NodeIP); err != nil {
		return err
	}

	if err := l.UpdatePodGateway(config.PodGateway); err != nil {
		return err
	}

	if err := l.UpdateAuthzOffload(config.AuthzOffload); err != nil {
		return err
	}

	if err := l.UpdateEnableMonitoring(config.EnableMonitoring); err != nil {
		return err
	}

	return nil
}

func (l *BpfLoader) GetKmeshConfigMap() factory.GlobalBpfConfig {
	return factory.GlobalBpfConfig{
		BpfLogLevel:      l.GetBpfLogLevel(),
		NodeIP:           l.GetNodeIP(),
		PodGateway:       l.GetPodGateway(),
		AuthzOffload:     l.GetAuthzOffload(),
		EnableMonitoring: l.GetEnableMonitoring(),
	}
}

func (l *BpfLoader) UpdateBpfLogLevel(BpfLogLevel uint32) error {
	if l.workloadObj != nil {
		if err := l.workloadObj.SockConn.BpfLogLevel.Set(BpfLogLevel); err != nil {
			return fmt.Errorf("set sockcon BpfLogLevel failed %w", err)
		}
		if err := l.workloadObj.SockOps.BpfLogLevel.Set(BpfLogLevel); err != nil {
			return fmt.Errorf("set sockops BpfLogLevel failed %w", err)
		}
		if err := l.workloadObj.XdpAuth.BpfLogLevel.Set(BpfLogLevel); err != nil {
			return fmt.Errorf("set xdp BpfLogLevel failed %w", err)
		}
		if err := l.workloadObj.SendMsg.BpfLogLevel.Set(BpfLogLevel); err != nil {
			return fmt.Errorf("set sendmsg BpfLogLevel failed %w", err)
		}
	} else if l.obj != nil {
		if err := l.obj.SockConn.BpfLogLevel.Set(BpfLogLevel); err != nil {
			return fmt.Errorf("set sockcon BpfLogLevel failed %w", err)
		}
		if err := l.obj.SockOps.BpfLogLevel.Set(BpfLogLevel); err != nil {
			return fmt.Errorf("set sockops BpfLogLevel failed %w", err)
		}
	}

	return nil
}

func (l *BpfLoader) GetBpfLogLevel() uint32 {
	if l.BpfLogLevel != nil {
		var BpfLogLevel uint32
		if err := l.BpfLogLevel.Get(&BpfLogLevel); err != nil {
			log.Errorf("get BpfLogLevel failed %v", err)
			return 0
		}
		return BpfLogLevel
	}

	return 0
}

func (l *BpfLoader) UpdateNodeIP(NodeIP [16]byte) error {
	if l.NodeIP != nil {
		if err := l.NodeIP.Set(NodeIP); err != nil {
			return fmt.Errorf("set NodeIP failed %w", err)
		}
	}

	return nil
}

func (l *BpfLoader) GetNodeIP() [16]byte {
	if l.NodeIP != nil {
		var NodeIP [16]byte
		if err := l.NodeIP.Get(&NodeIP); err != nil {
			log.Errorf("get NodeIP failed %v", err)
			return [16]byte{}
		}
		return NodeIP
	}
	return [16]byte{}
}

func (l *BpfLoader) UpdatePodGateway(PodGateway [16]byte) error {
	if l.PodGateway != nil {
		if err := l.PodGateway.Set(PodGateway); err != nil {
			return fmt.Errorf("set PodGateway failed %w", err)
		}
	}

	return nil
}

func (l *BpfLoader) GetPodGateway() [16]byte {
	if l.PodGateway != nil {
		var PodGateway [16]byte
		if err := l.PodGateway.Get(&PodGateway); err != nil {
			log.Errorf("get PodGateway failed %v", err)
			return [16]byte{}
		}
		return PodGateway
	}
	return [16]byte{}
}

func (l *BpfLoader) UpdateAuthzOffload(AuthzOffload uint32) error {
	if l.AuthzOffload != nil {
		if err := l.AuthzOffload.Set(AuthzOffload); err != nil {
			return fmt.Errorf("set AuthzOffload failed %w", err)
		}
	}

	return nil
}

func (l *BpfLoader) GetAuthzOffload() uint32 {
	if l.AuthzOffload != nil {
		var AuthzOffload uint32
		if err := l.AuthzOffload.Get(&AuthzOffload); err != nil {
			log.Errorf("get AuthzOffload failed %v", err)
			return 0
		}
		return AuthzOffload
	}
	return 0
}

func (l *BpfLoader) UpdateEnableMonitoring(EnableMonitoring uint32) error {
	if l.EnableMonitoring != nil {
		if err := l.EnableMonitoring.Set(EnableMonitoring); err != nil {
			return fmt.Errorf("set EnableMonitoring failed %w", err)
		}
	}

	return nil
}

func (l *BpfLoader) GetEnableMonitoring() uint32 {
	if l.EnableMonitoring != nil {
		var EnableMonitoring uint32
		if err := l.EnableMonitoring.Get(&EnableMonitoring); err != nil {
			log.Errorf("get EnableMonitoring failed %v", err)
			return 0
		}
		return EnableMonitoring
	}
	return 0
}

func closeMap(m *ebpf.Map) {
	if m == nil {
		return
	}

	if err := m.Unpin(); err != nil {
		log.Errorf("Failed to unpin kmesh_version: %v", err)
	}

	if err := m.Close(); err != nil {
		log.Errorf("Failed to close kmesh_version: %v", err)
	}

	log.Infof("cleaned kmesh_version map")
}

func CleanupBpfMap() {
	err := syscall.Unmount(constants.Cgroup2Path, 0)
	if err != nil {
		log.Errorf("unmount /mnt/kmesh_cgroup2 error: %v", err)
	}
	err = syscall.Unmount(constants.BpfFsPath, 0)
	if err != nil {
		log.Errorf("unmount /sys/fs/bpf error: %v", err)
	}
	err = os.RemoveAll(constants.Cgroup2Path)
	if err != nil {
		log.Errorf("remove /mnt/kmesh_cgroup2 error: %v", err)
	}
	log.Info("cleanup bpf map success")
}
