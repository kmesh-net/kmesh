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

package cni

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/cni/pkg/types"

	"kmesh.net/kmesh/pkg/constants"
)

type opts struct {
	CniMountNetEtcDIR string
	CniConfigName     string
	CniConfigChained  bool
}

func TestGetCniConfigPath(t *testing.T) {
	patches1 := gomonkey.NewPatches()
	patches2 := gomonkey.NewPatches()
	tests := []struct {
		name       string
		utconfig   opts
		beforeFunc func()
		afterFunc  func()
		wantErr    bool
	}{
		{
			name: "test1: have CniConfigName, get error in libcni.ConfListFromFile, should return error",
			utconfig: opts{
				CniConfigName:     "utTest.conflist",
				CniMountNetEtcDIR: "/etc/cni/net.d",
			},
			beforeFunc: func() {
				patches1.ApplyFunc(libcni.ConfListFromFile, func(filename string) (*libcni.NetworkConfigList, error) {
					return nil, errors.New("not found no such file or directory")
				})
			},
			afterFunc: func() {
				patches1.Reset()
			},
			wantErr: true,
		}, {
			name: "test2: have CniConfigName, no Plugins, should return error",
			utconfig: opts{
				CniConfigName:     "utTest.conflist",
				CniMountNetEtcDIR: "/etc/cni/net.d",
			},
			beforeFunc: func() {
				patches1.ApplyFunc(libcni.ConfListFromFile, func(filename string) (*libcni.NetworkConfigList, error) {
					return &libcni.NetworkConfigList{
						Name:         "utNetworkConfigList",
						CNIVersion:   "0.2.0",
						DisableCheck: true,
					}, nil
				})
			},
			afterFunc: func() {
				patches1.Reset()
			},
			wantErr: true,
		}, {
			name: "test3: no CniConfigName, get error in libcni.ConfFiles, should return error",
			utconfig: opts{
				CniMountNetEtcDIR: "/etc/cni/net.d",
			},
			beforeFunc: func() {
				patches1.ApplyFunc(libcni.ConfFiles, func(dir string, extensions []string) ([]string, error) {
					return nil, errors.New("not found no such file or directory")
				})
			},
			afterFunc: func() {
				patches1.Reset()
			},
			wantErr: true,
		}, {
			name: "test 4: no CniConfigName, get error in libcni.ConfListFromFile, should return error",
			utconfig: opts{
				CniMountNetEtcDIR: "/etc/cni/net.d",
			},
			beforeFunc: func() {
				patches1.ApplyFunc(libcni.ConfFiles, func(dir string, extensions []string) ([]string, error) {
					return []string{
						"utTest1.conflist",
						"utTest2.conflist",
					}, nil
				})
				patches2.ApplyFunc(libcni.ConfListFromFile, func(filename string) (*libcni.NetworkConfigList, error) {
					return nil, errors.New("not found no such file or directory")
				})
			},
			afterFunc: func() {
				patches1.Reset()
				patches2.Reset()
			},
			wantErr: true,
		}, {
			name: "test 5: no CniConfigName, no Plugins, should return error",
			utconfig: opts{
				CniMountNetEtcDIR: "/etc/cni/net.d",
			},
			beforeFunc: func() {
				patches1.ApplyFunc(libcni.ConfFiles, func(dir string, extensions []string) ([]string, error) {
					return []string{
						"utTest1.conflist",
						"utTest2.conflist",
					}, nil
				})
				patches2.ApplyFunc(libcni.ConfListFromFile, func(filename string) (*libcni.NetworkConfigList, error) {
					return &libcni.NetworkConfigList{
						Name:         "utNetworkConfigList",
						CNIVersion:   "0.2.0",
						DisableCheck: true,
					}, nil
				})
			},
			afterFunc: func() {
				patches1.Reset()
				patches2.Reset()
			},
			wantErr: true,
		}, {
			name: "test 6: have CniConfigName, get CnifigPath successful, should return nil",
			utconfig: opts{
				CniConfigName:     "utTest.conflist",
				CniMountNetEtcDIR: "/etc/cni/net.d",
			},
			beforeFunc: func() {
				patches1.ApplyFunc(libcni.ConfListFromFile, func(filename string) (*libcni.NetworkConfigList, error) {
					return &libcni.NetworkConfigList{
						Name:         "utNetworkConfigList",
						CNIVersion:   "0.2.0",
						DisableCheck: true,
						Plugins: []*libcni.NetworkConfig{
							{
								Network: &types.NetConf{
									CNIVersion: "0.2.0",
									Name:       "utTest",
								},
							},
						},
					}, nil
				})
			},
			afterFunc: func() {
				patches1.Reset()
			},
			wantErr: false,
		}, {
			name: "test 7: no CniConfigName, Successful, should return nil",
			utconfig: opts{
				CniMountNetEtcDIR: "/etc/cni/net.d",
			},
			beforeFunc: func() {
				patches1.ApplyFunc(libcni.ConfFiles, func(dir string, extensions []string) ([]string, error) {
					return []string{
						"utTest1.conflist",
						"utTest2.conflist",
					}, nil
				})
				patches2.ApplyFunc(libcni.ConfListFromFile, func(filename string) (*libcni.NetworkConfigList, error) {
					return &libcni.NetworkConfigList{
						Name:         "utNetworkConfigList",
						CNIVersion:   "0.2.0",
						DisableCheck: true,
						Plugins: []*libcni.NetworkConfig{
							{
								Network: &types.NetConf{
									CNIVersion: "0.2.0",
									Name:       "utTest",
								},
							},
						},
					}, nil
				})
			},
			afterFunc: func() {
				patches1.Reset()
				patches2.Reset()
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.utconfig
			tt.beforeFunc()
			i := NewInstaller(constants.AdsMode, config.CniMountNetEtcDIR, config.CniConfigName, config.CniConfigChained)
			_, err := i.getCniConfigPath()
			if (err != nil) != tt.wantErr {
				t.Errorf("getCniConfigPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.afterFunc()
		})
	}
}

func TestInsertCNIConfig(t *testing.T) {
	patches1 := gomonkey.NewPatches()
	tests := []struct {
		name       string
		utconfig   []byte
		beforeFunc func()
		afterFunc  func()
		wantErr    bool
	}{
		{
			name: "test1: failed to unmarshal json, should return error",
			utconfig: []byte(`{
				"cniVersion": "0.3.1",
				"name": "mynet",
				"plugins": [
					{
						"type": "calico"
					},
					{
						"type": "bandwidth"
					},
					{
						"invalid_json": "true"
					}
				]
			}`),
			beforeFunc: func() {
				patches1.ApplyFunc(json.Unmarshal, func(data []byte, v any) error {
					return errors.New("failed to unmarshal json")
				})
			},
			afterFunc: func() {
				patches1.Reset()
			},
			wantErr: true,
		},
		{
			name: "test2: can not found valid plugin list, should return error",
			utconfig: []byte(`{
				"cniVersion": "0.3.1",
				"name": "mynet",
				"invalid_key": "invalid_value"
			}`),
			beforeFunc: func() {},
			afterFunc:  func() {},
			wantErr:    true,
		},
		{
			name: "test3: failed to parser plugin, should return error",
			utconfig: []byte(`{
				"cniVersion": "0.3.1",
				"name": "mynet",
				"plugins": [
					{
						"type": "calico"
					},
					{
						"type": "bandwidth"
					},
					"invalid_plugin"
				]
			}`),
			beforeFunc: func() {},
			afterFunc:  func() {},
			wantErr:    true,
		},
		{
			name: "test4: plugins have kmesh-cni",
			utconfig: []byte(`{
				"cniVersion": "0.3.1",
				"name": "mynet",
				"plugins": [
					{
						"type": "calico"
					},
					{
						"type": "bandwidth"
					},
					{
						"type": "kmesh-cni",
						"kubeConfig": "/etc/cni/net.d/kmesh_kubeconfig.yaml"
					}
				]
			}`),
			beforeFunc: func() {},
			afterFunc:  func() {},
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.beforeFunc()
			i := NewInstaller(constants.AdsMode, "", "", true)
			_, err := i.insertCNIConfig(tt.utconfig, "workload")
			if (err != nil) != tt.wantErr {
				t.Errorf("insertCNIConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			tt.afterFunc()
		})
	}
}
