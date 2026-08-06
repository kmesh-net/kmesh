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

package maglev

import "testing"

// TestGetLookupTable_RespectsRequestedTableSize verifies that getLookupTable
// builds its permutation math against the tableSize argument it was given,
// not against the mutable package-level maglevTableSize. In production,
// maglevTableSize is only set once CreateLB -> InitMaglevMap has run against
// a live BPF pin; any caller that invokes getLookupTable before that (or with
// a tableSize that legitimately differs from the global, e.g. during a
// reconfigure) must not crash the process.
func TestGetLookupTable_RespectsRequestedTableSize(t *testing.T) {
	// Simulate the global being out of sync with the requested size --
	// exactly what happens if InitMaglevMap has not run yet (global stays
	// at its zero value) or a caller asks for a different table size.
	old := maglevTableSize
	defer func() { maglevTableSize = old }()
	maglevTableSize = 0

	cluster := newCluster()
	const requestedSize = 1201 // arbitrary, independent of the global

	table, err := getLookupTable(cluster, requestedSize)
	if err != nil {
		t.Fatalf("getLookupTable returned error: %v", err)
	}
	if len(table) != requestedSize {
		t.Fatalf("expected table of length %d, got %d", requestedSize, len(table))
	}
	for i, backendID := range table {
		if backendID < 0 {
			t.Fatalf("slot %d was never assigned a backend", i)
		}
	}
}
