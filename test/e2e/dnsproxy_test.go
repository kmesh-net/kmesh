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
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"istio.io/istio/pkg/test/framework"
	testKube "istio.io/istio/pkg/test/kube"
)

const (
	kmeshAdminPort = 15200
	dnsproxyPath   = "/dnsproxy"
)

// TestDnsproxyAPI tests enabling and disabling DNS proxy via the status server API (same as kmeshctl dnsproxy).
func TestDnsproxyAPI(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		cls := t.Clusters().Default()

		pods, err := testKube.CheckPodsAreReady(testKube.NewPodFetch(cls, KmeshNamespace, "app=kmesh"))
		if err != nil {
			t.Fatalf("failed to get kmesh pods: %v", err)
		}
		if len(pods) == 0 {
			t.Fatal("no kmesh pods found")
		}
		pod := pods[0]

		fw, err := cls.NewPortForwarder(pod.Name, pod.Namespace, "", 0, kmeshAdminPort)
		if err != nil {
			t.Fatalf("failed to create port forwarder: %v", err)
		}
		if err := fw.Start(); err != nil {
			t.Fatalf("failed to start port forwarder: %v", err)
		}
		defer fw.Close()

		baseURL := fmt.Sprintf("http://%s", fw.Address())

		t.NewSubTest("enable dnsproxy").Run(func(t framework.TestContext) {
			resp, err := postDnsproxy(baseURL, true)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode, "enable dnsproxy should return 200")
			}
		})

		t.NewSubTest("disable dnsproxy").Run(func(t framework.TestContext) {
			resp, err := postDnsproxy(baseURL, false)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode, "disable dnsproxy should return 200")
			}
		})

		t.NewSubTest("enable again then disable").Run(func(t framework.TestContext) {
			resp, err := postDnsproxy(baseURL, true)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			if resp != nil {
				resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}

			resp, err = postDnsproxy(baseURL, false)
			assert.NoError(t, err)
			assert.NotNil(t, resp)
			if resp != nil {
				resp.Body.Close()
				assert.Equal(t, http.StatusOK, resp.StatusCode)
			}
		})
	})
}

// postDnsproxy sends POST to /dnsproxy?enable=<true|false> on the status server.
func postDnsproxy(baseURL string, enable bool) (*http.Response, error) {
	enableStr := "false"
	if enable {
		enableStr = "true"
	}
	url := fmt.Sprintf("%s%s?enable=%s", baseURL, dnsproxyPath, enableStr)

	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 10 * time.Second}
	return client.Do(req)
}

// TestDnsproxyKmeshctl tests the ability to autonomously start and stop dnsProxy via kmeshctl.
func TestDnsproxyKmeshctl(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		cls := t.Clusters().Default()

		pods, err := testKube.CheckPodsAreReady(testKube.NewPodFetch(cls, KmeshNamespace, "app=kmesh"))
		if err != nil {
			t.Fatalf("failed to get kmesh pods: %v", err)
		}
		if len(pods) == 0 {
			t.Fatal("no kmesh pods found")
		}
		podName := pods[0].Name

		t.NewSubTest("kmeshctl dnsproxy enable").Run(func(t framework.TestContext) {
			cmd := exec.Command("kmeshctl", "dnsproxy", podName, "enable")
			out, err := cmd.CombinedOutput()
			assert.NoError(t, err, "kmeshctl dnsproxy enable should succeed: %s", string(out))
		})

		t.NewSubTest("kmeshctl dnsproxy disable").Run(func(t framework.TestContext) {
			cmd := exec.Command("kmeshctl", "dnsproxy", podName, "disable")
			out, err := cmd.CombinedOutput()
			assert.NoError(t, err, "kmeshctl dnsproxy disable should succeed: %s", string(out))
		})
	})
}

// TestDnsproxyStartupParameter verifies that DNS proxy can be controlled by startup parameter (--enable-dns-proxy).
// It patches the daemonset to add/remove the env KMESH_ENABLE_DNS_PROXY (backward compat) and ensures
// the daemon still runs; the actual DNS proxy state is driven by flag or env at startup.
func TestDnsproxyStartupParameter(t *testing.T) {
	framework.NewTest(t).Run(func(t framework.TestContext) {
		// Disable DNS proxy via env (backward compat with env)
		configureDNSProxy(t, false)

		// Ensure kmesh pods are still ready after disabling
		cls := t.Clusters().Default()
		_, err := testKube.CheckPodsAreReady(testKube.NewPodFetch(cls, KmeshNamespace, "app=kmesh"))
		assert.NoError(t, err)

		// Re-enable DNS proxy
		configureDNSProxy(t, true)

		_, err = testKube.CheckPodsAreReady(testKube.NewPodFetch(cls, KmeshNamespace, "app=kmesh"))
		assert.NoError(t, err)
	})
}
