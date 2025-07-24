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

package ipsec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
)

// DecodeHex is a utility function to decode a hex string into bytes.
func DecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestLoadIPSecKey tests the loading of IPSec keys from different file sources
func TestLoadIPSecKey(t *testing.T) {
	aeadKey := DecodeHex("2dc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462161")
	tests := []struct {
		name        string
		keyData     IpSecKey
		expectError bool
		errorMsg    string
	}{
		{ // Valid
			name: "valid_rfc4106_key",
			keyData: IpSecKey{
				Spi:         1,
				AeadKeyName: "rfc4106(gcm(aes))",
				AeadKey:     aeadKey,
				Length:      128,
			},
			expectError: false,
		},
		{
			name: "invalid_algo_name",
			keyData: IpSecKey{
				Spi:         3,
				AeadKeyName: "aes-gcm", // should start with "rfc"
				AeadKey:     aeadKey,
				Length:      128,
			},
			expectError: true,
			errorMsg:    "invalid algo name, aead need begin with \"rfc\"",
		},
		{
			name: "empty_algo_name",
			keyData: IpSecKey{
				Spi:         4,
				AeadKeyName: "",
				AeadKey:     aeadKey,
				Length:      128,
			},
			expectError: true,
			errorMsg:    "invalid algo name, aead need begin with \"rfc\"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temporary test file
			tmpDir := t.TempDir()
			relativePath := strings.TrimPrefix(IpSecKeyFile, "./") // Remove leading "./" for temp file path
			testFile := filepath.Join(tmpDir, relativePath)

			os.MkdirAll(filepath.Dir(testFile), 0755) // Ensure directory exists

			// Write test data to file
			keyJSON, err := json.Marshal(tt.keyData)
			require.NoError(t, err, "Failed to marshal test key data")

			err = os.WriteFile(testFile, keyJSON, 0644)
			require.NoError(t, err, "Failed to write test file")

			// Create handler and test
			handler := NewIpSecHandler()

			// Test the function
			err = handler.LoadIPSecKeyFromFile(testFile)

			if tt.expectError {
				assert.Error(t, err, "Expected error but got none")
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg, "Error message doesn't match expected")
				}
			} else {
				assert.NoError(t, err, "Unexpected error: %v", err)

				// Verify the key was loaded correctly
				assert.Equal(t, tt.keyData.Spi, handler.Spi, "SPI mismatch")

				// Check if key is stored in history
				storedKey, exists := handler.historyIpSecKey[tt.keyData.Spi]
				assert.True(t, exists, "Key not found in history")
				assert.Equal(t, tt.keyData.Spi, storedKey.Spi, "Stored SPI mismatch")
				assert.Equal(t, tt.keyData.AeadKeyName, storedKey.AeadKeyName, "Stored AeadKeyName mismatch")
				assert.Equal(t, tt.keyData.AeadKey, storedKey.AeadKey, "Stored AeadKey mismatch")
				assert.Equal(t, tt.keyData.Length, storedKey.Length, "Stored Length mismatch")
			}
		})
	}

	// Test invalid JSON format
	t.Run("invalid_json", func(t *testing.T) {
		tmpDir := t.TempDir()
		relatedPath := strings.TrimPrefix(IpSecKeyFile, "./") // Remove leading "./" for temp file path
		testFile := filepath.Join(tmpDir, relatedPath)
		os.MkdirAll(filepath.Dir(testFile), 0755) // Ensure directory exists

		invalidJSON := []byte(`{ invalid json }`) // Invalid key data
		// require.NoError(t, err, "Failed to marshal invalid key data")
		err := os.WriteFile(testFile, invalidJSON, 0644)
		require.NoError(t, err)

		handler := NewIpSecHandler()
		err = handler.LoadIPSecKeyFromFile(testFile)

		assert.Error(t, err, "Expected error for invalid JSON")
		assert.Contains(t, err.Error(), "ipsec config file decoder error", "Error should mention decoder error")
	})

	// Test file not found error
	t.Run("file_not_found", func(t *testing.T) {
		handler := NewIpSecHandler()

		err := handler.LoadIPSecKeyFromFile("/non/existent/file")

		assert.Error(t, err, "Expected error for non-existent file")
		assert.Contains(t, err.Error(), "load ipsec keys failed", "Error message should indicate file loading failure")
	})

	// Test multiple key loading (should update history)
	t.Run("multiple_key_loading", func(t *testing.T) {
		handler := NewIpSecHandler()
		tmpDir := t.TempDir()

		// Load first key
		key1 := IpSecKey{
			Spi:         1,
			AeadKeyName: "rfc4106(gcm(aes))",
			AeadKey:     aeadKey,
			Length:      128,
		}

		relatedPath := strings.TrimPrefix(IpSecKeyFile, "./") // Remove leading "./" for temp file path
		testFile := filepath.Join(tmpDir, relatedPath)
		os.MkdirAll(filepath.Dir(testFile), 0755) // Ensure directory exists

		key1JSON, err := json.Marshal(key1)
		require.NoError(t, err)
		err = os.WriteFile(testFile, key1JSON, 0644)
		require.NoError(t, err)

		err = handler.LoadIPSecKeyFromFile(testFile)
		assert.NoError(t, err)
		assert.Equal(t, 1, handler.Spi)
		assert.Len(t, handler.historyIpSecKey, 1)

		// Load second key with different SPI
		key2 := IpSecKey{
			Spi:         2,
			AeadKeyName: "rfc4106(gcm(aes))",
			AeadKey:     DecodeHex("abc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462161"),
			Length:      128,
		}
		key2JSON, err := json.Marshal(key2)
		require.NoError(t, err)
		err = os.WriteFile(testFile, key2JSON, 0644)
		require.NoError(t, err)

		err = handler.LoadIPSecKeyFromFile(testFile)
		assert.NoError(t, err)
		assert.Equal(t, 2, handler.Spi)           // Should update to latest
		assert.Len(t, handler.historyIpSecKey, 2) // Should keep both keys

		// Verify both keys are in history
		_, exists1 := handler.historyIpSecKey[1]
		_, exists2 := handler.historyIpSecKey[2]
		assert.True(t, exists1, "First key should still exist in history")
		assert.True(t, exists2, "Second key should exist in history")
	})
}

// TestGenerateIPSecKey tests the IPSec key generation algorithm.
func TestGenerateIPSecKey(t *testing.T) {
	handler := NewIpSecHandler()
	key := DecodeHex("2dc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462161")
	tests := []struct {
		name        string
		srcIP       string
		dstIP       string
		srcBootID   string
		dstBootID   string
		key         []byte
		description string
	}{
		{
			name:        "same_input_same_output",
			srcIP:       "10.0.0.1",
			dstIP:       "10.0.0.2",
			srcBootID:   "550e8400-e29b-41d4-a716-446655440000",
			dstBootID:   "550e8400-e29b-41d4-a716-446655440001",
			key:         key,
			description: "Same inputs should produce same output",
		},
		{
			name:        "different_src_different_output",
			srcIP:       "10.0.0.3", // Different src IP
			dstIP:       "10.0.0.2",
			srcBootID:   "550e8400-e29b-41d4-a716-446655440000",
			dstBootID:   "550e8400-e29b-41d4-a716-446655440001",
			key:         key,
			description: "Different src IP should produce different output",
		},
		{
			name:        "different_bootid_different_output",
			srcIP:       "10.0.0.1",
			dstIP:       "10.0.0.2",
			srcBootID:   "550e8400-e29b-41d4-a716-446655440002", // Different src Boot ID
			dstBootID:   "550e8400-e29b-41d4-a716-446655440001",
			key:         key,
			description: "Different boot ID should produce different output",
		},
		{
			name:        "different_key_different_output",
			srcIP:       "10.0.0.1",
			dstIP:       "10.0.0.2",
			srcBootID:   "550e8400-e29b-41d4-a716-446655440000",
			dstBootID:   "550e8400-e29b-41d4-a716-446655440001",
			key:         DecodeHex("2dc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462abc"), // Different key
			description: "Different key should produce different output",
		},
	}

	// Store reference result for comparison
	var referenceResult []byte

	for i, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := handler.generateIPSecKey(tt.srcIP, tt.dstIP, tt.srcBootID, tt.dstBootID, tt.key)

			// Basic validations
			assert.NotNil(t, result, "Result should not be nil")
			assert.Equal(t, len(tt.key), len(result), "Result length should match original key length")

			// For deterministic test, same input should produce same output
			if tt.name == "same_input_same_output" {
				result2 := handler.generateIPSecKey(tt.srcIP, tt.dstIP, tt.srcBootID, tt.dstBootID, tt.key)
				assert.Equal(t, result, result2, "Same inputs should produce identical results")
			}

			// Store reference for comparison
			if i == 0 { // Use first test as reference
				referenceResult = make([]byte, len(result))
				copy(referenceResult, result)
			}

			// Compare with reference (expect same or different based on test case)
			if i > 0 && referenceResult != nil {
				assert.NotEqual(t, referenceResult, result, tt.description)
			}
		})
	}
}

func hasStateRule(state *netlink.XfrmState) (bool, error) {
	// Verify the state was added
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		return false, err
	}

	found := false
	for _, s := range states {
		if s.Src.Equal(state.Src) && s.Dst.Equal(state.Dst) && s.Spi == state.Spi &&
			s.Proto == state.Proto && s.Mode == state.Mode &&
			s.Aead.Name == state.Aead.Name && s.Aead.Key != nil && bytes.Equal(s.Aead.Key, state.Aead.Key) &&
			s.Aead.ICVLen == state.Aead.ICVLen {
			found = true
		}
	}
	if !found {
		return false, nil
	}
	return true, nil
}

// TestCreateStateRule tests XFRM state creation logic
func TestCreateStateRule(t *testing.T) {
	handler := NewIpSecHandler()
	testKey := DecodeHex("2dc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462161")
	ipsecKey := IpSecKey{
		Spi:         1001,
		AeadKeyName: "rfc4106(gcm(aes))",
		AeadKey:     testKey,
		Length:      128,
	}

	src := net.ParseIP("10.0.1.100")
	dst := net.ParseIP("10.0.2.100")

	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   ipsecKey.Spi,
		Reqid: 1,
		Aead: &netlink.XfrmStateAlgo{
			Name:   ipsecKey.AeadKeyName,
			Key:    testKey,
			ICVLen: ipsecKey.Length,
		},
	}

	t.Run("test_create_state_rule", func(t *testing.T) {
		err := handler.createStateRule(state.Src, state.Dst, testKey, ipsecKey)

		if err != nil {
			t.Errorf("Failed to create XFRM state rule: %v", err)
			return
		}
		// Verify the state was added
		found, err := hasStateRule(state)
		if err != nil {
			t.Errorf("Failed to list XFRM states: %v", err)
			return
		}
		if !found {
			t.Errorf("XFRM state not found after creation: Src=%s, Dst=%s, Spi=%d", state.Src, state.Dst, state.Spi)
			return
		}

		state2 := *state
		state2.Src = net.ParseIP("10.0.3.100")
		state2.Dst = net.ParseIP("10.0.4.100")
		handler.createStateRule(state2.Src, state2.Dst, testKey, ipsecKey)
		// Verify the state was added
		found, err = hasStateRule(&state2)
		if err != nil {
			t.Errorf("Failed to list XFRM states: %v", err)
			return
		}
		if !found {
			t.Errorf("XFRM state not found after creation: Src=%s, Dst=%s, Spi=%d", state2.Src, state2.Dst, state2.Spi)
			return
		}
		// Test clean up state
		handler.Clean(dst.String()) // Clean up the state by passing the destination IP

		// Verify the state was removed
		found, err = hasStateRule(state)
		if err != nil {
			t.Errorf("Failed to list XFRM states after cleanup: %v", err)
			return
		}
		if found {
			t.Errorf("XFRM state still exists after cleanup: Src=%s, Dst=%s, Spi=%d", state.Src, state.Dst, state.Spi)
		}
		found, err = hasStateRule(&state2)
		if err != nil {
			t.Errorf("Failed to list XFRM states after cleanup: %v", err)
			return
		}
		if !found {
			t.Errorf("XFRM state not found after cleanup: Src=%s, Dst=%s, Spi=%d", state2.Src, state2.Dst, state2.Spi)
		}
	})
}

func hasPolicy(oldPolicy *netlink.XfrmPolicy, out bool) (bool, error) {
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return false, fmt.Errorf("Failed to list XFRM policies: %v", err)
	}

	found := false
	for _, p := range policies {
		eq := true
		eq = eq && (p.Src.String() == oldPolicy.Src.String())
		eq = eq && (p.Dst.String() == oldPolicy.Dst.String())
		eq = eq && (p.Tmpls[0].Spi == oldPolicy.Tmpls[0].Spi)
		eq = eq && (p.Tmpls[0].Src.Equal(oldPolicy.Tmpls[0].Src))
		eq = eq && (p.Tmpls[0].Dst.Equal(oldPolicy.Tmpls[0].Dst))
		if out {
			eq = eq && (p.Dir == netlink.XFRM_DIR_IN)
		} else {
			eq = eq && (p.Dir == netlink.XFRM_DIR_OUT)
		}
		eq = eq && (p.Tmpls[0].Mode == netlink.XFRM_MODE_TUNNEL)
		eq = eq && (p.Tmpls[0].Proto == netlink.XFRM_PROTO_ESP)
		if eq {
			found = true
			break
		}
	}
	if !found {
		return false, nil
	}
	return true, nil
}

// createAndVerifyPolicyRule is a helper function to create and verify an XFRM policy rule.
func createAndVerifyPolicyRule(t *testing.T, handler *IpSecHandler, policy *netlink.XfrmPolicy, out bool) {
	// Test ingress policy (out=true)
	err := handler.createPolicyRule(policy.Src, policy.Dst, policy.Tmpls[0].Src, policy.Tmpls[0].Dst, policy.Tmpls[0].Spi, out)
	if err != nil {
		t.Errorf("Failed to create XFRM policy rule: %v", err)
		return
	}
	// Verify the policy was added
	found, err := hasPolicy(policy, out)
	if err != nil {
		t.Errorf("Failed to check has XFRM policies: %v", err)
		return
	}
	if !found {
		t.Errorf("XFRM policy not found after creation: Src=%s, Dst=%s, Spi=%d", policy.Src, policy.Dst, policy.Tmpls[0].Spi)
		return
	}
}

// TestCreatePolicyRule tests XFRM policy creation logic
func TestCreatePolicyRule(t *testing.T) {
	handler := NewIpSecHandler()
	spi := 1001

	t.Run("test_policy_rule_ingress", func(t *testing.T) { // remote -> local
		_, srcCIDR, _ := net.ParseCIDR("0.0.0.0/0")     // remote pod CIDR
		_, dstCIDR, _ := net.ParseCIDR("10.244.1.0/24") // local pod CIDR
		src := net.ParseIP("10.0.2.100")                // remote nic IP
		dst := net.ParseIP("10.0.1.100")                // local nic IP
		policy := &netlink.XfrmPolicy{
			Src: srcCIDR,
			Dst: dstCIDR,
			Dir: netlink.XFRM_DIR_IN,
			Tmpls: []netlink.XfrmPolicyTmpl{
				{
					// Spi:   spi, // Spi is not used in ingress policy, but why?
					Src:   src,
					Dst:   dst,
					Mode:  netlink.XFRM_MODE_TUNNEL,
					Proto: netlink.XFRM_PROTO_ESP,
				},
			},
		}
		// Test ingress policy (out=true)
		createAndVerifyPolicyRule(t, handler, policy, true)
		// Test clean up
		handler.Clean(dst.String())
		// Verify the policy was removed
		found, err := hasPolicy(policy, true)
		if err != nil {
			t.Errorf("Failed to check has XFRM policies: %v", err)
			return
		}
		if found {
			t.Errorf("XFRM policy still exists after cleanup: Src=%s, Dst=%s, Spi=%d", policy.Src, policy.Dst, policy.Tmpls[0].Spi)
		}
	})

	t.Run("test_policy_rule_egress", func(t *testing.T) {
		_, srcCIDR, _ := net.ParseCIDR("0.0.0.0/0")     //  local pod CIDR
		_, dstCIDR, _ := net.ParseCIDR("10.244.1.0/24") // remote pod CIDR
		src := net.ParseIP("10.0.1.100")                // local nic IP
		dst := net.ParseIP("10.0.2.100")                // remote nic IP
		policy := &netlink.XfrmPolicy{
			Src: srcCIDR,
			Dst: dstCIDR,
			Dir: netlink.XFRM_DIR_OUT,
			Tmpls: []netlink.XfrmPolicyTmpl{
				{
					Spi:   spi,
					Src:   src,
					Dst:   dst,
					Mode:  netlink.XFRM_MODE_TUNNEL,
					Proto: netlink.XFRM_PROTO_ESP,
				},
			},
		}
		// Test egress policy (out=false)
		createAndVerifyPolicyRule(t, handler, policy, false)

		// Test clean up
		handler.Clean(src.String())
		// Verify the policy was removed
		found, err := hasPolicy(policy, false)
		if err != nil {
			t.Errorf("Failed to check has XFRM policies: %v", err)
			return
		}
		if found {
			t.Errorf("XFRM policy still exists after cleanup: Src=%s, Dst=%s, Spi=%d", policy.Src, policy.Dst, policy.Tmpls[0].Spi)
		}
	})
}

func TestFlush(t *testing.T) {
	handler := NewIpSecHandler()
	_, srcCIDR, _ := net.ParseCIDR("0.0.0.0/0")     //  local pod CIDR
	_, dstCIDR, _ := net.ParseCIDR("10.244.1.0/24") // remote pod CIDR
	src := net.ParseIP("10.0.1.100")                // local nic IP
	dst := net.ParseIP("10.0.2.100")                // remote nic IP

	spi := 1001
	policy := &netlink.XfrmPolicy{
		Src: srcCIDR,
		Dst: dstCIDR,
		Dir: netlink.XFRM_DIR_OUT,
		Tmpls: []netlink.XfrmPolicyTmpl{
			{
				Src:   src,
				Dst:   dst,
				Mode:  netlink.XFRM_MODE_TUNNEL,
				Proto: netlink.XFRM_PROTO_ESP,
			},
		},
	}

	// create state rule
	testKey := DecodeHex("2dc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462161")
	ipsecKey := IpSecKey{
		Spi:         1001,
		AeadKeyName: "rfc4106(gcm(aes))",
		AeadKey:     testKey,
		Length:      128,
	}
	state := &netlink.XfrmState{
		Src:   src,
		Dst:   dst,
		Proto: netlink.XFRM_PROTO_ESP,
		Mode:  netlink.XFRM_MODE_TUNNEL,
		Spi:   ipsecKey.Spi,
		Reqid: 1,
		Aead: &netlink.XfrmStateAlgo{
			Name:   ipsecKey.AeadKeyName,
			Key:    testKey,
			ICVLen: ipsecKey.Length,
		},
	}

	err := handler.createStateRule(state.Src, state.Dst, testKey, ipsecKey)
	if err != nil {
		t.Errorf("Failed to create XFRM state rule: %v", err)
		return
	}
	// Verify the state was added
	found, err := hasStateRule(state)
	if err != nil {
		t.Errorf("Failed to list XFRM states: %v", err)
		return
	}
	if !found {
		t.Errorf("XFRM state not found after creation: Src=%s, Dst=%s, Spi=%d", state.Src, state.Dst, state.Spi)
		return
	}
	// Create policy rule
	createAndVerifyPolicyRule(t, handler, policy, true)
	policy2 := *policy
	policy2.Tmpls[0].Src = net.ParseIP("10.0.3.100")
	policy2.Tmpls[0].Dst = net.ParseIP("10.0.4.100")
	policy2.Tmpls[0].Spi = spi
	createAndVerifyPolicyRule(t, handler, &policy2, false)

	// Flush all policies and states
	err = handler.Flush()
	if err != nil {
		t.Errorf("Failed to flush XFRM policies and states: %v", err)
		return
	}
	// Verify all states were removed
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	if err != nil {
		t.Errorf("Failed to list XFRM states after flush: %v", err)
		return
	}
	if len(states) != 0 {
		t.Errorf("XFRM states still exist after flush, count: %d", len(states))
		return
	}
	// Verify all policies were removed
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		t.Errorf("Failed to list XFRM policies after flush: %v", err)
		return
	}
	if len(policies) != 0 {
		t.Errorf("XFRM policies still exist after flush, count: %d", len(policies))
		return
	}
}
