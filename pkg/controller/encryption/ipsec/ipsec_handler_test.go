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

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/controller/encryption"
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
		keyData     encryption.IpSecKey
		expectError bool
		errorMsg    string
	}{
		{ // Valid
			name: "valid_rfc4106_key",
			keyData: encryption.IpSecKey{
				Spi:         1,
				AeadKeyName: "rfc4106(gcm(aes))",
				AeadKey:     aeadKey,
				Length:      128,
			},
			expectError: false,
		},
		{
			name: "invalid_algo_name",
			keyData: encryption.IpSecKey{
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
			keyData: encryption.IpSecKey{
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
	tests = []struct {
		name        string
		keyData     encryption.IpSecKey
		expectError bool
		errorMsg    string
	}{
		{
			name: "first_key",
			keyData: encryption.IpSecKey{
				Spi:         1,
				AeadKeyName: "rfc4106(gcm(aes))",
				AeadKey:     aeadKey,
				Length:      128,
			},
			expectError: false,
		},
		{
			name: "second_key",
			keyData: encryption.IpSecKey{
				Spi:         2,
				AeadKeyName: "rfc4106(gcm(aes))",
				AeadKey:     DecodeHex("abc9410d7cd6b324461bf16db518646594276c5362c30fc476ebca3f1a394b6ed4462161"),
				Length:      128,
			},
			expectError: false,
		},
	}
	t.Run("multiple_key_loading", func(t *testing.T) {
		handler := NewIpSecHandler()
		tmpDir := t.TempDir()
		relatedPath := strings.TrimPrefix(IpSecKeyFile, "./") // Remove leading "./" for temp file path
		testFile := filepath.Join(tmpDir, relatedPath)
		os.MkdirAll(filepath.Dir(testFile), 0755) // Ensure directory exists

		for i, tt := range tests {
			keyJSON, err := json.Marshal(tt.keyData)
			require.NoError(t, err)
			err = os.WriteFile(testFile, keyJSON, 0644)
			require.NoError(t, err)

			err = handler.LoadIPSecKeyFromFile(testFile)
			assert.NoError(t, err)

			assert.Equal(t, i+1, handler.Spi) // check spi
			assert.Len(t, handler.historyIpSecKey, i+1)
			_, exits := handler.historyIpSecKey[i+1] // check key exists
			assert.True(t, exits, "key not exists")
		}
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
			if state.OutputMark != nil {
				// If we expect a mark, the state from system must have a matching one.
				if s.OutputMark == nil || s.OutputMark.Value != state.OutputMark.Value {
					continue
				}
				// Special handling for Mask: allow 0 or 0xffffffff as equivalent
				if s.OutputMark.Mask != state.OutputMark.Mask && !(s.OutputMark.Mask == 0 && state.OutputMark.Mask == 0xffffffff) {
					continue
				}
			} else {
				// If we don't expect a mark, the state from system must not have one.
				if s.OutputMark != nil {
					continue
				}
			}
			found = true
			break
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
	ipsecKey := encryption.IpSecKey{
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
		err := handler.createStateRule(state.Src, state.Dst, testKey, ipsecKey, false)

		require.NoError(t, err, "Failed to add XFRM state rule: %v", err)
		// Verify the state was added
		found, err := hasStateRule(state)
		require.NoError(t, err, "Failed to check XFRM state rule: %v", err)
		require.True(t, found, "XFRM state rule not found after creation")

		state2 := *state
		state2.Src = net.ParseIP("10.0.3.100")
		state2.Dst = net.ParseIP("10.0.4.100")
		state2.OutputMark = &netlink.XfrmMark{
			Value: constants.XfrmDecryptedMark,
			Mask:  constants.XfrmMarkMask,
		}
		handler.createStateRule(state2.Src, state2.Dst, testKey, ipsecKey, true)
		// Verify the state was added
		found, err = hasStateRule(&state2)
		require.NoError(t, err, "Failed to check XFRM state rule: %v", err)
		require.True(t, found, "XFRM state rule not found after creation")

		// Test clean up state
		handler.Clean(dst.String()) // Clean up the state by passing the destination IP

		// Verify the state was removed
		found, err = hasStateRule(state)
		require.NoError(t, err, "Failed to check XFRM state rule: %v", err)
		require.False(t, found, "XFRM state rule found after deletion")
		found, err = hasStateRule(&state2)
		require.NoError(t, err, "Failed to check XFRM state rule: %v", err)
		require.True(t, found, "XFRM state2 rule should not be removed")
	})
}

func hasPolicy(oldPolicy *netlink.XfrmPolicy, out bool) (bool, error) {
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	if err != nil {
		return false, fmt.Errorf("Failed to list XFRM policies: %v", err)
	}

	found := false
	for _, p := range policies {
		if len(p.Tmpls) == 0 {
			continue
		}
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
	if len(policy.Tmpls) == 0 {
		t.Fatalf("no templates found in policy")
	}
	err := handler.createPolicyRule(policy.Src, policy.Dst, policy.Tmpls[0].Src, policy.Tmpls[0].Dst, policy.Tmpls[0].Spi, out)
	require.NoError(t, err, "Failed to create policy rule")

	// Verify the policy was added
	found, err := hasPolicy(policy, out)
	require.NoError(t, err, "Failed to verify policy")
	require.True(t, found, "Policy not found")
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
		require.NoError(t, err, "Failed to verify policy was removed")
		require.False(t, found, "Policy was not removed")
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
	ipsecKey := encryption.IpSecKey{
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

	err := handler.createStateRule(state.Src, state.Dst, testKey, ipsecKey, false)
	assert.NoError(t, err, "Failed to add state rule")
	// Verify the state was added
	found, err := hasStateRule(state)
	assert.NoError(t, err, "Failed to find state rule")
	assert.True(t, found, "State rule not found")

	// Create policy rule
	createAndVerifyPolicyRule(t, handler, policy, true)
	policy2 := *policy
	policy2.Tmpls[0].Src = net.ParseIP("10.0.3.100")
	policy2.Tmpls[0].Dst = net.ParseIP("10.0.4.100")
	policy2.Tmpls[0].Spi = spi
	createAndVerifyPolicyRule(t, handler, &policy2, false)

	// Flush all policies and states
	err = handler.Flush()
	require.NoError(t, err, "Failed to flush")

	// Verify all states were removed
	states, err := netlink.XfrmStateList(netlink.FAMILY_ALL)
	require.NoError(t, err, "Failed to list states")
	require.Equal(t, 0, len(states), "XFRM States still exist after flush")

	// Verify all policies were removed
	policies, err := netlink.XfrmPolicyList(netlink.FAMILY_ALL)
	require.NoError(t, err, "Failed to list policies")

	require.Equal(t, 0, len(policies), "XFRM policies still exist after flush")
}
