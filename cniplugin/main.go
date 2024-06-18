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

 * Author: bitcoffee
 * Create: 2023-11-19
 */

package main

import (
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/version"

	"kmesh.net/kmesh/pkg/cni/plugin"
)

const (
	CNI_PLUGIN_VERSION string = "0.0.1"
)

func main() {
	funcs := skel.CNIFuncs{
		Add:   plugin.CmdAdd,
		Del:   plugin.CmdDelete,
		Check: plugin.CmdCheck,
	}
	err := skel.PluginMainFuncsWithError(funcs, version.All,
		fmt.Sprintf("CNI plugin kmesh-cni %v", CNI_PLUGIN_VERSION))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
