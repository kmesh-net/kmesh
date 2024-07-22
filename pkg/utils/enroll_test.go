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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
			name: "test1: namespace with istio-injection=enabled, pod with sidecar inject annotation, should return false",
			args: args{
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
			want: false,
		}, {
			name: "test2: namespace with dataplane-mode=Kmesh, pod without sidecar inject annotation, should return true",
			args: args{
				pod: &corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "utPod",
						Namespace: "utNs",
					},
				},
			},
			want: true,
		}, {
			name: "test: namespace not found, should return error",
			args: args{
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
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ShouldEnroll(tt.args.pod, tt.args.namespace)
			if got != tt.want {
				t.Errorf("shouldEnroll() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldEnroll2(t *testing.T) {
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
			name: "pod managed by Kmesh",
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
			name: "pod not managed by Kmesh",
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
			name: "pod in namespace should managed by Kmesh",
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
			name: "pod in namespace should not managed by Kmesh",
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
			name: "waypoint should not managed by Kmesh",
			args: args{
				namespace: &corev1.Namespace{
					TypeMeta: metav1.TypeMeta{
						Kind:       "Namespace",
						APIVersion: "v1",
					},
					ObjectMeta: metav1.ObjectMeta{
						Name: "ut-test",
						Annotations: map[string]string{
							constants.KmeshRedirectionAnnotation: "enable",
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
