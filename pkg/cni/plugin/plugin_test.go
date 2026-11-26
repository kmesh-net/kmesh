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

package plugin

import (
	"testing"

	"github.com/containernetworking/cni/pkg/skel"
)

const chainedStdin = `{"cniVersion":"1.0.0","name":"kmesh","type":"kmesh-cni",` +
	`"prevResult":{"cniVersion":"1.0.0","interfaces":[{"name":"eth0"}],"ips":[]}}`

// A runtime may pass CNI_ARGS the plugin cannot load (a pair without '=' or an
// unknown key without IgnoreUnknown=1). CmdAdd must then fall back to printing
// the previous result, as it does for any other parse failure, not crash.
func TestCmdAddMalformedArgsPrintsPrevResult(t *testing.T) {
	args := &skel.CmdArgs{
		ContainerID: "abc",
		Netns:       "/var/run/netns/x",
		IfName:      "eth0",
		Args:        "K8S_POD_NAME=foo;THIS_HAS_NO_EQUALS_SIGN",
		StdinData:   []byte(chainedStdin),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("CmdAdd panicked: %v", r)
		}
	}()
	if err := CmdAdd(args); err != nil {
		t.Fatalf("expected the previous result to be printed, got error: %v", err)
	}
}

func TestParseSkelArgsKeepsConfOnBadArgs(t *testing.T) {
	args := &skel.CmdArgs{Args: "NOT_A_PAIR", StdinData: []byte(chainedStdin)}

	conf, k8s, prev, err := parseSkelArgs(args)
	if err == nil {
		t.Fatal("expected an error for malformed CNI_ARGS")
	}
	if k8s != nil {
		t.Fatalf("expected no k8s args, got %+v", k8s)
	}
	if conf == nil || conf.CNIVersion != "1.0.0" {
		t.Fatalf("expected the parsed config to be returned, got %+v", conf)
	}
	if prev == nil {
		t.Fatal("expected the previous result to be returned")
	}
}
