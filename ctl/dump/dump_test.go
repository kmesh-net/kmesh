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

package dump

import (
	"bytes"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	adminv2 "kmesh.net/kmesh/api/v2/admin"
	corev2 "kmesh.net/kmesh/api/v2/core"
	listenerv2 "kmesh.net/kmesh/api/v2/listener"
	"kmesh.net/kmesh/pkg/nets"
)

func TestPrintKernelNativeTableListenerPort(t *testing.T) {
	const listenerPort = 80

	configDump := &adminv2.ConfigDump{
		StaticResources: &adminv2.ConfigResources{
			ListenerConfigs: []*listenerv2.Listener{
				{
					Name: "listener_0.0.0.0:80",
					Address: &corev2.SocketAddress{
						Ipv4: 0,
						// The daemon stores listener ports in network byte order.
						Port: nets.ConvertPortToBigEndian(listenerPort),
					},
				},
			},
		},
	}

	body, err := protojson.Marshal(configDump)
	if err != nil {
		t.Fatalf("failed to marshal config dump: %v", err)
	}

	var out bytes.Buffer
	printKernelNativeTable(&out, body)

	output := out.String()
	var printedPort string
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 && fields[0] == "listener_0.0.0.0:80" {
			if len(fields) < 3 {
				t.Fatalf("malformed listener row %q", line)
			}
			printedPort = fields[2]
		}
	}
	if printedPort != "80" {
		t.Fatalf("expected listener port %d, got %q in output:\n%s", listenerPort, printedPort, output)
	}
}
