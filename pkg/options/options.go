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
 */

// Package options for parsing config
package options

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

var config DaemonConfig

type parseFactory interface {
	AttachFlags(cmd *cobra.Command)
	ParseConfig() error
}

// DaemonConfig describes the config factory, which can be registered by options.Register
type DaemonConfig []parseFactory

func (c *DaemonConfig) String() string {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("json marshal failed, %s", err)
	}

	return string(data)
}

// String format options.config to string
func String() string {
	return config.String()
}

// Register register the config factory
func Register(factory parseFactory) {
	config = append(config, factory)
}

func AttachFlags(cmd *cobra.Command) {
	for _, factory := range config {
		factory.AttachFlags(cmd)
	}
}

func ParseConfigs() error {
	for _, factory := range config {
		if err := factory.ParseConfig(); err != nil {
			return fmt.Errorf("parse config failed, %s", err)
		}
	}

	return nil
}

// IsYamlFormat verify whether yaml format file
func IsYamlFormat(path string) bool {
	ext := filepath.Ext(path)
	if ext == ".yaml" || ext == ".yml" {
		return true
	}
	return false
}

// LoadConfigFile load the config from the input file path
func LoadConfigFile(path string) ([]byte, error) {
	var (
		err     error
		content []byte
	)

	if content, err = os.ReadFile(path); err != nil {
		return nil, fmt.Errorf("%s read failed, %s", path, err)
	}

	if IsYamlFormat(path) {
		if content, err = yaml.YAMLToJSON(content); err != nil {
			return nil, fmt.Errorf("%s format to json failed, %s", path, err)
		}
	}

	return content, nil
}
