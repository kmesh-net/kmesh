/*
 * Copyright (c) 2019 Huawei Technologies Co., Ltd.
 * MeshAccelerating is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: LemmyHuang
 * Create: 2022-01-08
 */

package bpf

import (
	"flag"
	"openeuler.io/mesh/pkg/option"
	"os"
)

var config Config

func init() {
	option.Register(&config)
}

type Config struct {
	BpfFsPath    string
	Cgroup2Path    string
}

func (c *Config) SetArgs() error {
	flag.StringVar(&c.BpfFsPath, "bpfFsPath", "/sys/fs/bpf/", "bpf fs path")
	flag.StringVar(&c.Cgroup2Path, "cgroup2Path", "/mnt/cgroup2/", "cgroup2 path")

	return nil
}

func (c *Config) ParseConfig() error {
	if _, err := os.Stat(c.Cgroup2Path); err != nil {
		return err
	}
	if _, err := os.Stat(c.BpfFsPath); err != nil {
		return err
	}

	return nil
}
