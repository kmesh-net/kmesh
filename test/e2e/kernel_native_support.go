//go:build integ
// +build integ

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

package kmesh

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"istio.io/istio/pkg/test/framework"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func requireKernelNativeMode(t framework.TestContext) {
	if !envTrue(kernelNativeModeEnv) {
		t.Skipf("%s not set; skipping kernel-native e2e tests", kernelNativeModeEnv)
	}
	mode, err := getKmeshMode(t)
	if err != nil {
		t.Fatalf("failed to detect kmesh mode: %v", err)
	}
	if mode != "kernel-native" {
		t.Skipf("kmesh mode is %q; skipping kernel-native tests", mode)
	}
}

func requireEnhancedKernelForKernelNative(t framework.TestContext) {
	mode, err := getKmeshMode(t)
	if err != nil {
		t.Fatalf("failed to detect kmesh mode: %v", err)
	}
	if mode != "kernel-native" {
		return
	}
	enhanced, err := isEnhancedKernel(t)
	if err != nil {
		t.Fatalf("failed to detect enhanced kernel: %v", err)
	}
	if !enhanced {
		t.Skipf("kernel-native running without enhanced kernel; skipping L7/XDP/DNS tests")
	}
}

func isEnhancedKernel(t framework.TestContext) (bool, error) {
	pods, err := t.Clusters().Default().Kube().CoreV1().Pods(KmeshNamespace).
		List(context.Background(), metav1.ListOptions{LabelSelector: "app=kmesh"})
	if err != nil {
		return false, err
	}
	if len(pods.Items) == 0 {
		return false, fmt.Errorf("no kmesh pods found")
	}
	podName := pods.Items[0].Name
	tail := int64(200)
	req := t.Clusters().Default().Kube().CoreV1().Pods(KmeshNamespace).
		GetLogs(podName, &v1.PodLogOptions{TailLines: &tail})
	stream, err := req.Stream(context.Background())
	if err != nil {
		return false, err
	}
	defer stream.Close()
	data, err := io.ReadAll(stream)
	if err != nil {
		return false, err
	}
	logs := string(data)
	if strings.Contains(logs, "kmesh start with Enhanced") || strings.Contains(logs, "kmesh start with enhanced") {
		return true, nil
	}
	if strings.Contains(logs, "kmesh start with Normal") || strings.Contains(logs, "kmesh start with normal") {
		return false, nil
	}
	return false, fmt.Errorf("unable to determine kernel type from kmesh logs")
}

func getKmeshMode(t framework.TestContext) (string, error) {
	ds, err := t.Clusters().Default().Kube().AppsV1().DaemonSets(KmeshNamespace).
		Get(context.Background(), KmeshDaemonsetName, metav1.GetOptions{})
	if err != nil {
		return "", err
	}

	for _, c := range ds.Spec.Template.Spec.Containers {
		if c.Name != "kmesh" {
			continue
		}
		candidates := append([]string{}, c.Args...)
		candidates = append(candidates, c.Command...)
		for _, arg := range candidates {
			if strings.HasPrefix(arg, "--mode=") {
				return strings.TrimPrefix(arg, "--mode="), nil
			}
			if strings.Contains(arg, "--mode=") {
				// Covers cases like "/bin/sh -c ./start_kmesh.sh --mode=kernel-native ..."
				parts := strings.Fields(arg)
				for _, part := range parts {
					if strings.HasPrefix(part, "--mode=") {
						return strings.TrimPrefix(part, "--mode="), nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("--mode arg not found in kmesh daemonset")
}

func envTrue(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "1" || v == "true" || v == "yes"
}

func getEnvInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
