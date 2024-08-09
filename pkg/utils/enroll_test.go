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

package utils

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"istio.io/api/annotation"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"kmesh.net/kmesh/pkg/constants"
)

func TestShouldEnroll(t *testing.T) {
	type args struct {
		namespace *corev1.Namespace
		pod       *corev1.Pod
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "pod with label",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
					},
				},
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ut-test",
						Name:      "ut-pod",
						Labels: map[string]string{
							constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh,
						},
					},
				},
			},
			want: true,
		},
		{
			name: "pod with hostnetwork",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
					},
				},
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ut-test",
						Name:      "ut-pod",
						Labels: map[string]string{
							constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh,
						},
					},
					Spec: corev1.PodSpec{
						HostNetwork: true,
					},
				},
			},
			want: false,
		},
		{
			name: "sidecar misconfigured label",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
					},
				},
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ut-test",
						Name:      "ut-pod",
						Labels: map[string]string{
							constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh,
						},
						Annotations: map[string]string{
							annotation.SidecarStatus.Name: "",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "pod and namespace without label",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
					},
				},
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ut-test",
						Name:      "ut-pod",
					},
				},
			},
			want: false,
		},
		{
			name: "namespace with label",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
						Labels: map[string]string{
							constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh,
						},
					},
				},
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ut-test",
						Name:      "ut-pod",
					},
				},
			},
			want: true,
		},
		{
			name: "pod with none label not managed by Kmesh",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
						Labels: map[string]string{
							constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh,
						},
					},
				},
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ut-test",
						Name:      "ut-pod",
						Labels: map[string]string{
							constants.DataPlaneModeLabel: "none",
						},
					},
				},
			},
			want: false,
		},
		{
			name: "waypoint should not managed by Kmesh",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
						Labels: map[string]string{
							constants.DataPlaneModeLabel: constants.DataPlaneModeKmesh,
						},
					},
				},
				pod: &corev1.Pod{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Namespace: "ut-test",
						Name:      "ut-waypoint",
						Labels: map[string]string{
							"gateway.istio.io/managed": "istio.io-mesh-controller",
						},
					},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldEnroll(tt.args.pod, tt.args.namespace); got != tt.want {
				t.Errorf("shouldEnroll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHandleKmeshManage(t *testing.T) {
	type args struct {
		ns     string
		enroll bool
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "enroll true",
			args: args{
				enroll: true,
			},
			wantErr: false,
		},
		{
			name: "enroll false",
			args: args{
				enroll: false,
			},
			wantErr: false,
		},
		{
			name: "enroll false",
			args: args{
				ns:     "invalid ns",
				enroll: false,
			},
			wantErr: true,
		},
	}
	pid := os.Getpid()
	ns := fmt.Sprintf("/proc/%d/ns/net", pid)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.args.ns != "" {
				err = HandleKmeshManage(tt.args.ns, tt.args.enroll)
			} else {
				err = HandleKmeshManage(ns, tt.args.enroll)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("HandleKmeshManage() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
func TestPatchKmeshRedirectAnnotation(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "test-namespace"
	podName := "test-pod"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      podName,
		},
	}

	_, err := client.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = PatchKmeshRedirectAnnotation(client, pod)
	if err != nil {
		t.Errorf("PatchKmeshRedirectAnnotation() returned an error: %v", err)
	}

	got, err := client.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		t.Errorf("Failed to get the patched pod: %v", err)
	}

	if !AnnotationEnabled(got.Annotations[constants.KmeshRedirectionAnnotation]) {
		t.Errorf("Expected annotation %s to be 'enabled', got '%s'", constants.KmeshRedirectionAnnotation, got.Annotations[constants.KmeshRedirectionAnnotation])
	}

	err = PatchKmeshRedirectAnnotation(client, got)
	if err != nil {
		t.Errorf("PatchKmeshRedirectAnnotation() returned an error: %v", err)
	}

	got, err = client.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		t.Errorf("Failed to get the patched pod: %v", err)
	}

	if !AnnotationEnabled(got.Annotations[constants.KmeshRedirectionAnnotation]) {
		t.Errorf("Expected annotation %s to be 'enabled', got '%s'", constants.KmeshRedirectionAnnotation, got.Annotations[constants.KmeshRedirectionAnnotation])
	}
}

func TestDelKmeshRedirectAnnotation(t *testing.T) {
	client := fake.NewSimpleClientset()
	namespace := "test-namespace"
	podName := "test-pod"
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      podName,
			Annotations: map[string]string{
				constants.KmeshRedirectionAnnotation: "enabled",
			},
		},
	}

	_, err := client.CoreV1().Pods(namespace).Create(context.Background(), pod, metav1.CreateOptions{})
	assert.NoError(t, err)

	err = DelKmeshRedirectAnnotation(client, pod)
	if err != nil {
		t.Errorf("DelKmeshRedirectAnnotation() returned an error: %v", err)
	}

	got, err := client.CoreV1().Pods(namespace).Get(context.Background(), podName, metav1.GetOptions{})
	if err != nil {
		t.Errorf("Failed to get patched pod: %v", err)
	}

	if _, exists := got.Annotations[constants.KmeshRedirectionAnnotation]; exists {
		t.Errorf("Annotation %s was not deleted from pod %s in namespace %s", constants.KmeshRedirectionAnnotation, podName, namespace)
	}

	err = DelKmeshRedirectAnnotation(client, pod)
	if err != nil {
		t.Errorf("DelKmeshRedirectAnnotation() returned an error: %v", err)
	}
}
