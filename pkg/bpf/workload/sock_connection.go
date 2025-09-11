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

package workload

import (
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/dualengine"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/general"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/constants"
	helper "kmesh.net/kmesh/pkg/utils"
)

type SockConnWorkload struct {
	Info        general.BpfInfo
	Link        link.Link
	Info6       general.BpfInfo
	Link6       link.Link
	InfoDns4    general.BpfInfo
	LinkDns4    link.Link
	InfoDnsRcv4 general.BpfInfo
	LinkDnsRcv4 link.Link
	bpf2go.KmeshCgroupSockWorkloadObjects
}

func (sc *SockConnWorkload) NewBpf(cfg *options.BpfConfig) error {
	sc.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh_workload/map/"
	sc.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh_workload/sockconn/"
	sc.Info.Cgroup2Path = cfg.Cgroup2Path
	sc.Info6 = sc.Info
	sc.InfoDns4 = sc.Info
	sc.InfoDnsRcv4 = sc.Info

	if err := os.MkdirAll(sc.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(sc.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (sc *SockConnWorkload) loadKmeshSockConnObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshCgroupSockWorkloadCompat()
	} else {
		spec, err = bpf2go.LoadKmeshCgroupSockWorkload()
	}
	if err != nil || spec == nil {
		return nil, err
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshCgroupSockWorkloadObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *SockConnWorkload) LoadSockConn() error {
	/* load kmesh sockops main bpf prog */
	spec, err := sc.loadKmeshSockConnObjects()
	if err != nil {
		return err
	}
	prog := spec.Programs["cgroup_connect4_prog"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	if err = sc.KmCgrTailcall.Update(
		uint32(constants.TailCallConnect4Index),
		uint32(sc.CgroupConnect4Prog.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}

	prog = spec.Programs["cgroup_connect6_prog"]
	sc.Info6.Type = prog.Type
	sc.Info6.AttachType = prog.AttachType

	if err = sc.KmCgrTailcall.Update(
		uint32(constants.TailCallConnect6Index),
		uint32(sc.CgroupConnect6Prog.FD()),
		ebpf.UpdateAny); err != nil {
		return err
	}

	prog = spec.Programs["bpf_redirect_dns_send"]
	sc.InfoDns4.Type = prog.Type
	sc.InfoDns4.AttachType = prog.AttachType

	prog = spec.Programs["bpf_restore_dns_recv"]
	sc.InfoDnsRcv4.Type = prog.Type
	sc.InfoDnsRcv4.AttachType = prog.AttachType
	return nil
}

func (sc *SockConnWorkload) close() error {
	if err := sc.KmeshCgroupSockWorkloadObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (sc *SockConnWorkload) Attach() error {
	var err error
	cgopt4 := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.CgroupConnect4Prog,
	}

	cgopt6 := link.CgroupOptions{
		Path:    sc.Info6.Cgroup2Path,
		Attach:  sc.Info6.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.CgroupConnect6Prog,
	}

	cgoptdns4 := link.CgroupOptions{
		Path:    sc.InfoDns4.Cgroup2Path,
		Attach:  sc.InfoDns4.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.BpfRedirectDnsSend,
	}

	cgoptdnsrecv4 := link.CgroupOptions{
		Path:    sc.InfoDnsRcv4.Cgroup2Path,
		Attach:  sc.InfoDnsRcv4.AttachType,
		Program: sc.KmeshCgroupSockWorkloadObjects.BpfRestoreDnsRecv,
	}

	pinPath4 := filepath.Join(sc.Info.BpfFsPath, "sockconn_prog")
	pinPath6 := filepath.Join(sc.Info.BpfFsPath, "sockconn6_prog")
	pinPathDns4 := filepath.Join(sc.Info.BpfFsPath, "sockconn_dns_prog")
	pinPathDnsRecv4 := filepath.Join(sc.Info.BpfFsPath, "sockconn_dns_recv_prog")

	if restart.GetStartType() == restart.Restart || restart.GetStartType() == restart.Update {
		if sc.Link, err = utils.BpfProgUpdate(pinPath4, cgopt4); err != nil {
			return err
		}

		if sc.Link6, err = utils.BpfProgUpdate(pinPath6, cgopt6); err != nil {
			return err
		}

		if sc.LinkDns4, err = utils.BpfProgUpdate(pinPathDns4, cgoptdns4); err != nil {
			return err
		}

		if sc.LinkDnsRcv4, err = utils.BpfProgUpdate(pinPathDnsRecv4, cgoptdnsrecv4); err != nil {
			return err
		}
	} else {
		sc.Link, err = link.AttachCgroup(cgopt4)
		if err != nil {
			return err
		}

		if err := sc.Link.Pin(pinPath4); err != nil {
			return err
		}

		sc.Link6, err = link.AttachCgroup(cgopt6)
		if err != nil {
			return err
		}

		if err := sc.Link6.Pin(pinPath6); err != nil {
			return err
		}

		sc.LinkDns4, err = link.AttachCgroup(cgoptdns4)
		if err != nil {
			return err
		}

		if err := sc.LinkDns4.Pin(pinPathDns4); err != nil {
			return err
		}

		sc.LinkDnsRcv4, err = link.AttachCgroup(cgoptdnsrecv4)
		if err != nil {
			return err
		}
		if err := sc.LinkDnsRcv4.Pin(pinPathDnsRecv4); err != nil {
			return err
		}
	}

	return err
}

func (sc *SockConnWorkload) Detach() error {
	var value reflect.Value

	if err := sc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadPrograms)
	if err := utils.UnpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.KmeshCgroupSockWorkloadObjects.KmeshCgroupSockWorkloadMaps)
	if err := utils.UnpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(sc.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.Link != nil {
		return sc.Link.Close()
	}

	if err := os.RemoveAll(sc.Info6.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.Link6 != nil {
		return sc.Link6.Close()
	}
	return nil
}
