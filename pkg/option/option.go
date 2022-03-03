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
 * Create: 2021-10-09
 */

package option

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sigs.k8s.io/yaml"
	"strings"
)

var (
	argLists = os.Args[1:]
	config DaemonConfig
)

type parseFactory interface {
	SetArgs() error
	ParseConfig() error
}
type DaemonConfig []parseFactory

func (c *DaemonConfig) String() string {
	var str = ""
	for _, factory := range *c {
		str += fmt.Sprintf("%#v \n", factory)
	}

	return str
}

func Register(factory parseFactory) {
	config = append(config, factory)
}

func InitDaemonConfig() error {
	var err error

	for _, factory := range config {
		if err = factory.SetArgs(); err != nil {
			flag.Usage()
			return fmt.Errorf("set args failed, %s", err)
		}
	}
	flag.Parse()

	for _, factory := range config {
		if err = factory.ParseConfig(); err != nil {
			return fmt.Errorf("parse config failed, %s", err)
		}
	}

	fmt.Println(config.String())
	return nil
}

func FindArgIndex(name string) int {
	for i, arg := range argLists {
		if strings.Contains(arg, name) {
			return i
		}
	}

	return -1
}

func GetArgValue(index int) string {
	if len(argLists) <= index {
		return ""
	}

	arg := argLists[index]
	if j := strings.Index(arg, "="); j != -1 {
		if len(arg) - 1 > j {
			return arg[j+1:]
		}
	} else {
		if len(argLists) - 1 > index {
			return argLists[index+1]
		}
	}

	return ""
}

func IsYamlFormat(path string) bool {
	ext := filepath.Ext(path)
	if ext == ".yaml" || ext == ".yml" {
		return true
	}
	return false
}

func LoadConfigFile(path string) ([]byte, error) {
	var (
		err       error
		content   []byte
	)

	if content, err = ioutil.ReadFile(path); err != nil {
		return nil, fmt.Errorf("%s read failed, %s", path, err)
	}

	if IsYamlFormat(path) {
		if content, err = yaml.YAMLToJSON(content); err != nil {
			return nil, fmt.Errorf("%s format to json failed, %s", path, err)
		}
	}

	return content, nil
}
