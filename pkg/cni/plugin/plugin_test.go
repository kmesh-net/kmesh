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
 *
 * Author: bitcoffee
 * Create: 2023-11-19
 */

package plugin

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"kmesh.net/kmesh/pkg/utils"
)

func TestCheckKmesh(t *testing.T) {
	type args struct {
		client kubernetes.Interface
		pod    *corev1.Pod
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "test1: namespace with istio-injection=enabled, pod with sidecar inject annotation, should return false",
			args: args{
				client: fake.NewSimpleClientset(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "utNs",
						Labels: map[string]string{
							"istio-injection": "ebable",
						},
					},
				}),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "utPod",
						Namespace: "utNs",
						Annotations: map[string]string{
							"sidecar.istio.io/inject": "true",
						},
					},
				},
			},
			want:    false,
			wantErr: false,
		}, {
			name: "test2: namespace with dataplane-mode=Kmesh, pod without sidecar inject annotation, should return true",
			args: args{
				client: fake.NewSimpleClientset(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "utNs",
						Labels: map[string]string{
							"istio.io/dataplane-mode": "kmesh",
						},
					},
				}),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "utPod",
						Namespace: "utNs",
					},
				},
			},
			want:    true,
			wantErr: false,
		}, {
			name: "test: namespace not found, should return error",
			args: args{
				client: fake.NewSimpleClientset(&corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: "otherNs",
					},
				}),
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "utPod",
						Namespace: "utNs",
						Labels: map[string]string{
							"istio.io/dataplane-mode": "Kmesh",
						},
					},
				},
			},
			want:    false,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := checkKmesh(tt.args.client, tt.args.pod)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkKmesh() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("checkKmesh() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestKmeshCtlByClassid(t *testing.T) {
	utPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			UID:       types.UID("utpod"),
			Name:      "utPod",
			Namespace: "utNs",
		},
	}
	fakeClient := fake.NewSimpleClientset(utPod)
	patches1 := gomonkey.NewPatches()
	patches2 := gomonkey.NewPatches()
	tests := []struct {
		name       string
		wantErr    bool
		beforeFunc func()
		afterFunc  func()
	}{
		{
			name:    "test1: failed to open new cls, should return err",
			wantErr: true,
			beforeFunc: func() {
				patches1.ApplyFunc(os.OpenFile, func(name string, flag int, perm fs.FileMode) (*os.File, error) {
					return nil, errors.New("permission denied")
				})
			},
			afterFunc: func() {
				patches1.Reset()
			},
		}, {
			name:    "test2: failed to exec cmd with redirect, should return err",
			wantErr: true,
			beforeFunc: func() {
				patches1.ApplyFunc(os.OpenFile, func(name string, flag int, perm fs.FileMode) (*os.File, error) {
					return nil, nil
				})
				patches2.ApplyFunc(utils.ExecuteWithRedirect, func(cmd string, args []string, stdout io.Writer) error {
					return errors.New("permission denied")
				})
			},
			afterFunc: func() {
				patches1.Reset()
				patches2.Reset()
			},
		}, {
			name:    "test3: no error, should return nil",
			wantErr: false,
			beforeFunc: func() {
				patches1.ApplyFunc(os.OpenFile, func(name string, flag int, perm fs.FileMode) (*os.File, error) {
					return nil, nil
				})
				patches2.ApplyFunc(utils.ExecuteWithRedirect, func(cmd string, args []string, stdout io.Writer) error {
					return nil
				})
			},
			afterFunc: func() {
				patches1.Reset()
				patches2.Reset()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.beforeFunc()
			err := kmeshCtlByClassid(fakeClient, utPod)
			if err != nil && !tt.wantErr {
				t.Errorf("%v", err)
			}
			tt.afterFunc()
		})
	}
}
