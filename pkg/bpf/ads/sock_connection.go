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

package ads

// #cgo pkg-config: bpf api-v2-c
// #include "kmesh/ads/include/tail_call_index.h"
// #include "inner_map_defs.h"
import "C"
import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpf2go "kmesh.net/kmesh/bpf/kmesh/bpf2go/kernelnative/normal"
	"kmesh.net/kmesh/daemon/options"
	"kmesh.net/kmesh/pkg/bpf/restart"
	"kmesh.net/kmesh/pkg/bpf/utils"
	"kmesh.net/kmesh/pkg/constants"
	helper "kmesh.net/kmesh/pkg/utils"
)

var KMESH_TAIL_CALL_LISTENER = uint32(C.KMESH_TAIL_CALL_LISTENER)
var KMESH_TAIL_CALL_FILTER_CHAIN = uint32(C.KMESH_TAIL_CALL_FILTER_CHAIN)
var KMESH_TAIL_CALL_FILTER = uint32(C.KMESH_TAIL_CALL_FILTER)
var KMESH_TAIL_CALL_ROUTER = uint32(C.KMESH_TAIL_CALL_ROUTER)
var KMESH_TAIL_CALL_CLUSTER = uint32(C.KMESH_TAIL_CALL_CLUSTER)
var KMESH_TAIL_CALL_ROUTER_CONFIG = uint32(C.KMESH_TAIL_CALL_ROUTER_CONFIG)

type BpfInfo struct {
	MapPath     string
	BpfFsPath   string
	Cgroup2Path string

	Type       ebpf.ProgramType
	AttachType ebpf.AttachType
}

type BpfSockConn struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshCgroupSockObjects
}

func (sc *BpfSockConn) NewBpf(cfg *options.BpfConfig) error {
	sc.Info.MapPath = cfg.BpfFsPath + "/bpf_kmesh/map/"
	sc.Info.BpfFsPath = cfg.BpfFsPath + "/bpf_kmesh/sockconn/"
	sc.Info.Cgroup2Path = cfg.Cgroup2Path

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

func (sc *BpfSockConn) loadKmeshSockConnObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath

	if helper.KernelVersionLowerThan5_13() {
		spec, err = bpf2go.LoadKmeshCgroupSockCompat()
	} else {
		spec, err = bpf2go.LoadKmeshCgroupSock()
	}
	if err != nil || spec == nil {
		return nil, err
	}

	utils.SetMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshCgroupSockObjects, &opts); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfSockConn) Load() error {
	/* load kmesh sockops main bpf prog */
	spec, err := sc.loadKmeshSockConnObjects()
	if err != nil {
		log.Errorf("loadKmeshSockConnObjects failed: %v", err)
		return err
	}

	prog := spec.Programs["cgroup_connect4_prog"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	// update tail call prog
	err = sc.KmCgrptailcall.Update(
		uint32(KMESH_TAIL_CALL_FILTER_CHAIN),
		uint32(sc.FilterChainManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return err
	}

	err = sc.KmCgrptailcall.Update(
		uint32(KMESH_TAIL_CALL_FILTER),
		uint32(sc.FilterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return err
	}

	err = sc.KmCgrptailcall.Update(
		uint32(KMESH_TAIL_CALL_CLUSTER),
		uint32(sc.ClusterManager.FD()),
		ebpf.UpdateAny)
	if err != nil {
		return err
	}

	return nil
}

func (sc *BpfSockConn) close() error {
	if err := sc.KmeshCgroupSockObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfSockConn) Attach() error {
	var err error
	cgopt := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshCgroupSockObjects.CgroupConnect4Prog,
	}

	progPinPath := filepath.Join(sc.Info.BpfFsPath, constants.Prog_link)
	tree()
	if restart.GetStartType() == restart.Restart {
		if sc.Link, err = utils.BpfProgUpdate(progPinPath, cgopt); err != nil {
			return err
		}

	} else {
		sc.Link, err = link.AttachCgroup(cgopt)
		if err != nil {
			return fmt.Errorf("AttachCgroup %s failed: %v", sc.Info.Cgroup2Path, err)
		}

		if err := sc.Link.Pin(progPinPath); err != nil {
			return fmt.Errorf("Pin %s failed: %v", progPinPath, err)
		}
	}
	return nil
}

func tree() {
	fmt.Println("attacch")
	root := []string{"/sys/fs/bpf"}
	for _, r := range root {
		// Walk the directory tree
		err := filepath.Walk(r, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// Print the file or directory name with indentation
			fmt.Printf("%s%s\n", getIndentation(path, r), info.Name())
			return nil
		})

		if err != nil {
			log.Fatal(err)
		}
	}
}

// getIndentation returns the indentation for a given path
func getIndentation(path, root string) string {
	relativePath, err := filepath.Rel(root, path)
	if err != nil {
		return ""
	}
	depth := len(strings.Split(relativePath, string(filepath.Separator)))
	res := ""
	for i := 0; i < depth; i++ {
		res += "  "
	}
	return res
}

func (sc *BpfSockConn) Detach() error {
	var value reflect.Value

	if err := sc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.KmeshCgroupSockObjects.KmeshCgroupSockPrograms)
	if err := utils.UnpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.KmeshCgroupSockObjects.KmeshCgroupSockMaps)
	if err := utils.UnpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(sc.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.Link != nil {
		return sc.Link.Close()
	}
	return nil
}
