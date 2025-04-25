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
	"bufio"
	"context"
	"crypto/rand"
    "encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	v1 "k8s.io/api/core/v1"
    metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
    "kmesh.net/kmesh/ctl/utils"
)

func runVersionCmd(args ...string) (string, error) {
	cmdArgs := append([]string{"version"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func findKmeshPod(t *testing.T) string {
	const ns = "kmesh-system"
	const label = "app=kmesh"
	cmd := exec.Command("kubectl", "-n", ns, "get", "pods",
		"-l", label, "-o", "jsonpath={.items[0].metadata.name}")
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		list := exec.Command("kubectl", "-n", ns, "get", "pods", "-o", "wide")
		all, _ := list.CombinedOutput()
		t.Fatalf("could not find pod with label %q: %v\nPods:\n%s", label, err, string(all))
	}
	name := strings.TrimSpace(string(out))
	t.Logf("Found Kmesh pod: %s", name)
	return name
}

func waitForPodRunning(t *testing.T, pod string) {
	const ns = "kmesh-system"
	const retries = 20
	const delay = 2 * time.Second
	for i := 0; i < retries; i++ {
		cmd := exec.Command("kubectl", "-n", ns, "get", "pod", pod, "-o", "jsonpath={.status.phase}")
		out, err := cmd.Output()
		if err == nil && strings.EqualFold(strings.TrimSpace(string(out)), "Running") {
			t.Logf("Pod %s is Running", pod)
			return
		}
		time.Sleep(delay)
	}
	t.Fatalf("pod %s did not become Running in time", pod)
}

func TestKmeshctlVersion(t *testing.T) {
	pod := findKmeshPod(t)
	waitForPodRunning(t, pod)

	t.Run("client-and-daemon-summary", func(t *testing.T) {
		out, err := runVersionCmd()
		t.Logf("Output of 'kmeshctl version':\n%s", out)
		if err != nil {
			t.Fatalf("version command failed: %v", err)
		}
		if !strings.Contains(out, "client version:") {
			t.Errorf("expected 'client version:' in output, got:\n%s", out)
		}
		if !strings.Contains(out, "kmesh-daemon version:") {
			t.Errorf("expected 'kmesh-daemon version:' in output, got:\n%s", out)
		}
	})

	t.Run("daemon-version-json", func(t *testing.T) {
		out, err := runVersionCmd(pod)
		t.Logf("Output of 'kmeshctl version %s':\n%s", pod, out)
		if err != nil {
			t.Fatalf("version <pod> command failed: %v", err)
		}
		var info struct {
			GitVersion string `json:"GitVersion"`
			GitCommit  string `json:"GitCommit"`
		}
		if err := json.Unmarshal([]byte(out), &info); err != nil {
			t.Fatalf("invalid JSON output: %v", err)
		}
		if info.GitVersion == "" || info.GitCommit == "" {
			t.Errorf("expected non-empty GitVersion and GitCommit, got: %+v", info)
		}
	})
}

func runDumpCmd(args ...string) (string, error) {
	cmdArgs := append([]string{"dump"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
 }

 func TestKmeshctlDump(t *testing.T) {
    pod := findKmeshPod(t)
    waitForPodRunning(t, pod)

    t.Run("kernel-native", func(t *testing.T) {
        out, err := runDumpCmd(pod, "kernel-native")
        t.Logf("Output of 'kmeshctl dump %s kernel-native':\n%s", pod, out)

        if strings.Contains(out, "Invalid Client Mode") {
            t.Log("kernel-native not supported; got expected error")
            return
        }
        if err != nil {
            t.Fatalf("dump kernel-native failed: %v\n%s", err, out)
        }
        if !strings.Contains(out, `"workloads"`) {
            t.Errorf("expected JSON to contain \"workloads\" array, got:\n%s", out)
        }
        if !strings.Contains(out, `"services"`) {
            t.Errorf("expected JSON to contain \"services\" array, got:\n%s", out)
        }
    })

    t.Run("dual-engine", func(t *testing.T) {
        out, err := runDumpCmd(pod, "dual-engine")
        t.Logf("Output of 'kmeshctl dump %s dual-engine':\n%s", pod, out)
        if err != nil {
            t.Fatalf("dump dual-engine failed: %v\n%s", err, out)
        }
        if !strings.Contains(out, `"workloads"`) {
            t.Errorf("expected JSON to contain \"workloads\" array, got:\n%s", out)
        }
        if !strings.Contains(out, `"services"`) {
            t.Errorf("expected JSON to contain \"services\" array, got:\n%s", out)
        }
    })

    t.Run("invalid-mode", func(t *testing.T) {
        out, err := runDumpCmd(pod, "invalid-mode")
        t.Logf("Output of 'kmeshctl dump %s invalid-mode':\n%s", pod, out)
        if err == nil {
            t.Fatal("expected error for invalid mode, but command succeeded")
        }
        if !strings.Contains(out, "Argument must be 'kernel-native' or 'dual-engine'") {
            t.Errorf("expected usage error, got:\n%s", out)
        }
    })
}
  
 func runAccesslogCmd(args ...string) (string, error) {
	cmdArgs := append([]string{"monitoring"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
 }

 func TestKmeshctlAccesslog(t *testing.T) {
	pod := findKmeshPod(t)
	waitForPodRunning(t, pod)
 
 
	t.Run("enable-on-pod", func(t *testing.T) {
		out, err := runAccesslogCmd(pod, "--accesslog", "enable")
		t.Logf("enable-on-pod output:\n%s", out)
		if err != nil {
			t.Fatalf("failed to enable accesslog on pod %s: %v", pod, err)
		}
	})
 
 
	t.Run("disable-on-pod", func(t *testing.T) {
		out, err := runAccesslogCmd(pod, "--accesslog", "disable")
		t.Logf("disable-on-pod output:\n%s", out)
		if err != nil {
			t.Fatalf("failed to disable accesslog on pod %s: %v", pod, err)
		}
	})
 
 
	t.Run("enable-cluster", func(t *testing.T) {
		out, err := runAccesslogCmd("--accesslog", "enable")
		t.Logf("enable-cluster output:\n%s", out)
		if err != nil {
			t.Fatalf("failed to enable accesslog cluster-wide: %v", err)
		}
	})
 
 
	t.Run("disable-cluster", func(t *testing.T) {
		out, err := runAccesslogCmd("--accesslog", "disable")
		t.Logf("disable-cluster output:\n%s", out)
		if err != nil {
			t.Fatalf("failed to disable accesslog cluster-wide: %v", err)
		}
	})
 }

 func getLogOutputs(args ...string) (string, error) {
	cmdArgs := append([]string{"log"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
 }
 
 
 func verifyLogOutputHeaders(t *testing.T, output, expectedHeader string) {
	scanner := bufio.NewScanner(strings.NewReader(output))
	found := false
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, expectedHeader) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected output to contain header %q but it did not. Full output:\n%s", expectedHeader, output)
	}
 }

 func TestKmeshctlLog(t *testing.T) {
	podName := findKmeshPod(t)
	waitForPodRunning(t, podName)
 
	t.Run("get-all-loggers", func(t *testing.T) {
		output, err := getLogOutputs(podName)
		if err != nil {
			t.Fatalf("Failed to get logger names: %v, output: %s", err, output)
		}
		t.Logf("Output of 'kmeshctl log %s':\n%s", podName, output)
		verifyLogOutputHeaders(t, output, "Existing Loggers:")
	})
 
	t.Run("get-default-logger-level", func(t *testing.T) {
		output, err := getLogOutputs(podName, "default")
		if err != nil {
			t.Fatalf("Failed to get default logger level: %v, output: %s", err, output)
		}
		t.Logf("Output of 'kmeshctl log %s default':\n%s", podName, output)
		if !strings.Contains(output, "Logger Name:") || !strings.Contains(output, "Logger Level:") {
			t.Errorf("Expected output to contain 'Logger Name:' and 'Logger Level:', but got: %s", output)
		}
	})
 
 
	t.Run("set-default-logger-level", func(t *testing.T) {
		output, err := getLogOutputs(podName, "--set", "default:debug")
		if err != nil {
			t.Fatalf("Failed to set default logger level: %v, output: %s", err, output)
		}
		t.Logf("Output of 'kmeshctl log %s --set default:debug':\n%s", podName, output)
		output2, err := getLogOutputs(podName, "default")
		if err != nil {
			t.Fatalf("Failed to get default logger level after setting: %v, output: %s", err, output2)
		}
		t.Logf("Output of 'kmeshctl log %s default' after setting:\n%s", podName, output2)
		if !strings.Contains(strings.ToLower(output2), "debug") {
			t.Errorf("Expected default logger level to be 'debug', but output was: %s", output2)
		}
	})
 }
 
 type IpSecKey struct {
	AeadKeyName string `json:"AeadKeyName"`
	AeadKey     []byte `json:"AeadKey"`
	Length      int    `json:"Length"`
	Spi         int    `json:"Spi"`
 }
 
 
 func waitForSecret(secretName, namespace string, timeout time.Duration) (*v1.Secret, error) {
	clientset, err := utils.CreateKubeClient()
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %v", err)
	}
 
 
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		sec, err := clientset.Kube().CoreV1().Secrets(namespace).Get(context.TODO(), secretName, metav1.GetOptions{})
		if err == nil {
			return sec, nil
		}
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("timeout waiting for secret %q in namespace %q", secretName, namespace)
 }
 
 func deleteSecret(secretName, namespace string) error {
	clientset, err := utils.CreateKubeClient()
	if err != nil {
		return fmt.Errorf("failed to create kube client: %v", err)
	}
	_ = clientset.Kube().CoreV1().Secrets(namespace).Delete(context.TODO(), secretName, metav1.DeleteOptions{})
	return nil
 }
 
 func generateRandomKey() (string, error) {
	keyBytes := make([]byte, 36)
	_, err := rand.Read(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random key: %v", err)
	}
	return hex.EncodeToString(keyBytes), nil
 }
 
 
 func TestKmeshctlSecret(t *testing.T) {
	const secretName = "kmesh-ipsec"
	const namespace = "kmesh-system"
 
	_ = deleteSecret(secretName, namespace)
	t.Log("Deleted existing secret (if any)")
 
 
	key1, err := generateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}
	t.Logf("Generated key1: %s", key1)
 
 
	cmd := exec.Command("kmeshctl", "secret", "--key", key1)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run kmeshctl secret command: %v, output: %s", err, string(output))
	}
	t.Logf("Output of first 'kmeshctl secret' command: %s", string(output))
 
 
	sec, err := waitForSecret(secretName, namespace, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to get created secret: %v", err)
	}
 
	dataB64, exists := sec.Data["ipSec"]
	if !exists {
		t.Fatalf("secret %q does not contain key 'ipSec'", secretName)
	}

	var ipSecKey IpSecKey
	err = json.Unmarshal(dataB64, &ipSecKey)
	if err != nil {
		t.Fatalf("failed to unmarshal secret data: %v", err)
	}
	t.Logf("Created secret with SPI: %d", ipSecKey.Spi)
	if ipSecKey.Spi != 1 {
		t.Errorf("Expected SPI to be 1 on creation, got %d", ipSecKey.Spi)
	}

	key2, err := generateRandomKey()
	if err != nil {
		t.Fatalf("failed to generate second random key: %v", err)
	}
	t.Logf("Generated key2: %s", key2)
	cmd = exec.Command("kmeshctl", "secret", "--key", key2)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to run kmeshctl secret command for update: %v, output: %s", err, string(output))
	}
	t.Logf("Output of second 'kmeshctl secret' command: %s", string(output))
 

	secUpdated, err := waitForSecret(secretName, namespace, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to get updated secret: %v", err)
	}
	dataB64 = secUpdated.Data["ipSec"]
	var ipSecKeyUpdated IpSecKey
	err = json.Unmarshal(dataB64, &ipSecKeyUpdated)
	if err != nil {
		t.Fatalf("failed to unmarshal updated secret data: %v", err)
	}
	t.Logf("Updated secret with SPI: %d", ipSecKeyUpdated.Spi)
	expectedSPI := ipSecKey.Spi + 1
	if ipSecKeyUpdated.Spi != expectedSPI {
		t.Errorf("Expected updated SPI to be %d, but got %d", expectedSPI, ipSecKeyUpdated.Spi)
	}
 }
 
 func runAuthzCmd(args ...string) (string, error) {
	cmdArgs := append([]string{"authz"}, args...)
	cmd := exec.Command("kmeshctl", cmdArgs...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
 
func TestKmeshctlAuthzEnableDisable(t *testing.T) {
	pod := findKmeshPod(t)
	waitForPodRunning(t, pod)

	t.Run("enable-cluster", func(t *testing.T) {
		out, err := runAuthzCmd("enable")
		t.Logf("Output of 'kmeshctl authz enable':\n%s", out)
		if err != nil {
			t.Fatalf("cluster-wide enable failed: %v", err)
		}
	})

	t.Run("disable-cluster", func(t *testing.T) {
		out, err := runAuthzCmd("disable")
		t.Logf("Output of 'kmeshctl authz disable':\n%s", out)
		if err != nil {
			t.Fatalf("cluster-wide disable failed: %v", err)
		}
	})

	t.Run("enable-pod", func(t *testing.T) {
		out, err := runAuthzCmd("enable", pod)
		t.Logf("Output of 'kmeshctl authz enable %s':\n%s", pod, out)
		if err != nil {
			t.Fatalf("per-pod enable failed: %v", err)
		}
	})

	t.Run("disable-pod", func(t *testing.T) {
		out, err := runAuthzCmd("disable", pod)
		t.Logf("Output of 'kmeshctl authz disable %s':\n%s", pod, out)
		if err != nil {
			t.Fatalf("per-pod disable failed: %v", err)
		}
	})
}