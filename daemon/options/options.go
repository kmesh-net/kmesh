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

// Package options for parsing config
package options

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

type BootstrapConfigs struct {
	BpfConfig *BpfConfig
	CniConfig *cniConfig
}

func NewBootstrapConfigs() *BootstrapConfigs {
	return &BootstrapConfigs{
		BpfConfig: &BpfConfig{},
		CniConfig: &cniConfig{},
	}
}

func (c *BootstrapConfigs) String() string {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Sprintf("json marshal failed, %s", err)
	}

	return string(data)
}

func (c *BootstrapConfigs) AttachFlags(cmd *cobra.Command) {
	c.BpfConfig.AttachFlags(cmd)
	c.CniConfig.AttachFlags(cmd)
}

func (c *BootstrapConfigs) ParseConfigs() error {
	if err := c.BpfConfig.ParseConfig(); err != nil {
		return fmt.Errorf("parse BpfConfig failed, %s", err)
	}
	if err := c.CniConfig.ParseConfig(); err != nil {
		return fmt.Errorf("parse CniConfig failed, %s", err)
	}
	return nil
}
