//go:build linux && (amd64 || arm64) && !aix && !ppc64

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

package bpftests

import (
	"testing"

	"github.com/cilium/ebpf"

	"kmesh.net/kmesh/pkg/bpf/factory"
	"kmesh.net/kmesh/pkg/constants"
)

func testGeneralTC(t *testing.T) {
	TCtests := []unitTests_BPF_PROG_TEST_RUN{
		{
			objFilename: "tc_mark_encrypt_test.o",
			uts: []unitTest_BPF_PROG_TEST_RUN{
				{
					name: "tc_mark_encrypt",
					setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel: constants.BPF_LOG_DEBUG,
						})
					},
				},
			},
		},
		{
			objFilename: "tc_mark_decrypt_test.o",
			uts: []unitTest_BPF_PROG_TEST_RUN{
				{
					name: "tc_mark_decrypt",
					setupInUserSpace: func(t *testing.T, coll *ebpf.Collection) {
						setBpfConfig(t, coll, &factory.GlobalBpfConfig{
							BpfLogLevel: constants.BPF_LOG_DEBUG,
						})
					},
				},
			},
		},
	}

	for _, tt := range TCtests {
		t.Run(tt.objFilename, tt.run())
	}
}
