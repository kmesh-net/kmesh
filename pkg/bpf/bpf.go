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

package bpf

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("pkg/bpf")

type BpfInfo struct {
	Config
	MapPath    string
	Type       ebpf.ProgramType
	AttachType ebpf.AttachType
}

type BpfObject struct {
	Kmesh BpfKmesh
}

var Obj BpfObject

func StartKmesh() error {
	var err error

	if Obj.Kmesh, err = NewBpfKmesh(&config); err != nil {
		return err
	}

	if err = Obj.Kmesh.Load(); err != nil {
		Stop()
		return fmt.Errorf("bpf Load failed, %s", err)
	}

	if err = Obj.Kmesh.Attach(); err != nil {
		Stop()
		return fmt.Errorf("bpf Attach failed, %s", err)
	}

	if err = Obj.Kmesh.ApiEnvCfg(); err != nil {
		Stop()
		return fmt.Errorf("api env config failed, %s", err)
	}

	return nil
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

func Start() error {
	var err error

	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}

	if err = mountCgroup2(&config); err != nil {
		return err
	}

	if config.EnableKmesh {
		if err = StartKmesh(); err != nil {
			return err
		}
	} else if config.EnableKmeshWorkload {
		if err = StartKmeshWorkload(); err != nil {
			return err
		}
	}

	if config.EnableMda {
		if err = StartMda(); err != nil {
			return err
		}
	}

	return nil
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

func Stop() {
	var err error

	if config.EnableKmesh {
		if err = Obj.Kmesh.Detach(); err != nil {
			log.Errorf("failed detach when stop kmesh, err:%s", err)
			return
		}
	} else if config.EnableKmeshWorkload {
		if err = ObjWorkload.KmeshWorkload.Detach(); err != nil {
			log.Errorf("failed detach when stop kmesh, err:%s", err)
			return
		}
	}

	if config.EnableMda {
		if err = StopMda(); err != nil {
			log.Errorf("failed disable mda when stop kmesh, err:%s", err)
			return
		}
	}
}

func mountCgroup2(cfg *Config) error {
	if err := os.MkdirAll(cfg.Cgroup2Path, 0755); err != nil {
		log.Errorf("failed to create dir %s: %v", cfg.Cgroup2Path, err)
		return err
	}

	if err := syscall.Mount("none", cfg.Cgroup2Path, "cgroup2", 0, ""); err != nil {
		log.Errorf("failed to mount %s: %v", cfg.Cgroup2Path, err)
		return err
	}

	return nil
}
