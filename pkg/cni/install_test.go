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

package cni

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"istio.io/istio/pkg/test/util/retry"

	"kmesh.net/kmesh/pkg/constants"
)

func TestWatchTokenFile(t *testing.T) {
	serviceAccountPath := t.TempDir()
	os.WriteFile(filepath.Join(serviceAccountPath, "token"), []byte("faketoken"), 0o644)
	os.WriteFile(filepath.Join(serviceAccountPath, "ca.crt"), []byte("fakecacert"), 0o644)

	os.Setenv("KUBERNETES_SERVICE_HOST", "10.96.0.1")
	os.Setenv("KUBERNETES_SERVICE_PORT", "443")

	expectedKC, err := createKubeConfig(serviceAccountPath)
	if err != nil {
		t.Fatalf("failed to create expected kubeconfig: %v", err)
	}

	cniDir := t.TempDir()

	i := NewInstaller(constants.WorkloadMode, cniDir, "conflist-name", true, serviceAccountPath)
	defer i.Watcher.Close()

	kubeconfigPath := filepath.Join(i.CniMountNetEtcDIR, kmeshCniKubeConfig)
	if err := maybeWriteKubeConfigFile(serviceAccountPath, kubeconfigPath); err != nil {
		t.Fatalf("failed to write kubeconfig file: %v", err)
	}

	existingKC, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		t.Fatalf("failed to read the content of existing kubeconfig path: %v", err)
	}

	if expectedKC != string(existingKC) {
		t.Fatalf("existing kubeconfig\n%s\n***is NOT equal to*** expected kubeconfig\n%s\n", existingKC, expectedKC)
	}

	if err := i.WatchServiceAccountToken(); err != nil {
		t.Fatalf("failed to watch service account token: %v", err)
	}

	os.WriteFile(filepath.Join(serviceAccountPath, "token"), []byte("updatedfaketoken"), 0o644)

	retry.UntilSuccess(func() error {
		expectedKC, err = createKubeConfig(serviceAccountPath)
		if err != nil {
			return fmt.Errorf("failed to create expected kubeconfig after token update: %v", err)
		}

		existingKC, err = os.ReadFile(kubeconfigPath)
		if err != nil {
			return fmt.Errorf("failed to read the content of existing kubeconfig path update token update: %v", err)
		}

		if expectedKC != string(existingKC) {
			return fmt.Errorf("existing kubeconfig\n%s\n***is NOT equal to*** expected kubeconfig\n%s\nafter token update", existingKC, expectedKC)
		}

		return nil
	}, retry.Timeout(3*time.Second))
}
