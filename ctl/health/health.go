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

package health

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"kmesh.net/kmesh/ctl/utils"
	"kmesh.net/kmesh/pkg/kube"
)

const patternReady = "/debug/ready"

// FetchDaemonHealth GETs a daemon /debug/ready URL.
// ready is true when the response is HTTP 200 and the body trims to "OK".
func FetchDaemonHealth(url string) (ready bool, body string, err error) {
	resp, err := http.Get(url)
	if err != nil {
		return false, "", fmt.Errorf("failed to make HTTP request(%s): %w", url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, "", fmt.Errorf("failed to read HTTP response body(%s): %w", url, err)
	}
	body = string(raw)
	if resp.StatusCode != http.StatusOK {
		return false, body, fmt.Errorf("received status code %d from %s, body: %s", resp.StatusCode, url, body)
	}
	return strings.TrimSpace(body) == "OK", body, nil
}

// GetDaemonHealth port-forwards to a kmesh-daemon pod and checks /debug/ready.
func GetDaemonHealth(client kube.CLIClient, podName string) (bool, error) {
	fw, err := utils.CreateKmeshPortForwarder(client, podName)
	if err != nil {
		return false, fmt.Errorf("failed to create port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	if err := fw.Start(); err != nil {
		return false, fmt.Errorf("failed to start port forwarder for Kmesh daemon pod %s: %w", podName, err)
	}
	defer fw.Close()

	url := fmt.Sprintf("http://%s%s", fw.Address(), patternReady)
	ready, _, err := FetchDaemonHealth(url)
	return ready, err
}
