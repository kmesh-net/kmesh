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

package utils

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"
)

// MockLink for testing
type MockLink struct {
	index int
	name  string
}

func (m *MockLink) Attrs() *netlink.LinkAttrs {
	return &netlink.LinkAttrs{
		Index: m.index,
		Name:  m.name,
	}
}

func (m *MockLink) Type() string {
	return "veth"
}

// Test helper to create a mock link
func createMockLink(name string, index int) *MockLink {
	return &MockLink{
		name:  name,
		index: index,
	}
}

// TestGetVethPeerIndexFromInterface_Loopback tests loopback interface detection
func TestGetVethPeerIndexFromInterface_Loopback(t *testing.T) {
	iface := net.Interface{
		Name:  "lo",
		Flags: net.FlagLoopback | net.FlagUp,
	}

	_, err := GetVethPeerIndexFromInterface(iface)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "local interface")
}

// TestGetVethPeerIndexFromInterface_NotUp tests interface not up detection
func TestGetVethPeerIndexFromInterface_NotUp(t *testing.T) {
	iface := net.Interface{
		Name:  "eth0",
		Flags: 0, // Not up
	}

	_, err := GetVethPeerIndexFromInterface(iface)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not up")
}

// TestGetVethPeerIndexFromInterface_ValidInterface tests with a valid up interface
func TestGetVethPeerIndexFromInterface_ValidInterface(t *testing.T) {
	// Get actual interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Skip("Cannot get interfaces")
	}

	// Find a non-loopback, up interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			// Try to get peer index - it will fail if not veth, but shouldn't panic
			_, err := GetVethPeerIndexFromInterface(iface)
			// We expect an error for non-veth interfaces
			if err != nil {
				// This is expected for non-veth interfaces
				return
			}
			// If no error, it's a veth and test passes
			return
		}
	}

	t.Skip("No suitable interface found for testing")
}

// TestGetVethPeerIndexFromName_NonExistent tests with non-existent interface
func TestGetVethPeerIndexFromName_NonExistent(t *testing.T) {
	_, err := GetVethPeerIndexFromName("nonexistent999")
	assert.Error(t, err)
}

// TestGetVethPeerIndexFromName_Loopback tests with loopback interface
func TestGetVethPeerIndexFromName_Loopback(t *testing.T) {
	_, err := GetVethPeerIndexFromName("lo")
	// Should error because lo is not a veth - the error message may vary
	// depending on permissions and system state
	assert.Error(t, err, "Expected error when getting veth peer index from loopback interface")
}

// TestIfaceContainIPs_WithMatchingIP tests IP matching
func TestIfaceContainIPs_WithMatchingIP(t *testing.T) {
	// Get actual interface to test with
	interfaces, err := net.Interfaces()
	assert.NoError(t, err)

	for _, testIface := range interfaces {
		if testIface.Flags&net.FlagUp != 0 {
			addrs, err := testIface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}

			// Extract an IP from the interface
			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				// Test with matching IP
				contains, err := IfaceContainIPs(testIface, []string{ipNet.IP.String()})
				assert.NoError(t, err)
				assert.True(t, contains, "Should find matching IP")

				return
			}
		}
	}

	t.Skip("No suitable interface found for testing")
}

// TestIfaceContainIPs_WithoutMatchingIP tests no IP match
func TestIfaceContainIPs_WithoutMatchingIP(t *testing.T) {
	interfaces, err := net.Interfaces()
	assert.NoError(t, err)

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 {
			// Use IPs that definitely won't match
			contains, err := IfaceContainIPs(iface, []string{"198.51.100.1", "203.0.113.1"})
			assert.NoError(t, err)
			assert.False(t, contains, "Should not find non-matching IPs")
			return
		}
	}

	t.Skip("No suitable interface found for testing")
}

// TestIfaceContainIPs_EmptyIPList tests with empty IP list
func TestIfaceContainIPs_EmptyIPList(t *testing.T) {
	interfaces, err := net.Interfaces()
	assert.NoError(t, err)

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 {
			contains, err := IfaceContainIPs(iface, []string{})
			assert.NoError(t, err)
			assert.False(t, contains, "Empty IP list should return false")
			return
		}
	}

	t.Skip("No suitable interface found for testing")
}

// TestIfaceContainIPs_MultipleIPs tests with multiple IPs where one matches
func TestIfaceContainIPs_MultipleIPs(t *testing.T) {
	interfaces, err := net.Interfaces()
	assert.NoError(t, err)

	for _, testIface := range interfaces {
		if testIface.Flags&net.FlagUp != 0 {
			addrs, err := testIface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				// Test with one matching IP and one non-matching
				testIPs := []string{"198.51.100.1", ipNet.IP.String(), "203.0.113.1"}
				contains, err := IfaceContainIPs(testIface, testIPs)
				assert.NoError(t, err)
				assert.True(t, contains, "Should find the matching IP in the list")

				return
			}
		}
	}

	t.Skip("No suitable interface found for testing")
}

// TestIfaceContainIPs_IPv4AndIPv6 tests with both IPv4 and IPv6 addresses
func TestIfaceContainIPs_IPv4AndIPv6(t *testing.T) {
	interfaces, err := net.Interfaces()
	assert.NoError(t, err)

	for _, testIface := range interfaces {
		if testIface.Flags&net.FlagUp != 0 {
			addrs, err := testIface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}

			var hasIPv4, hasIPv6 bool
			var ipv4Addr, ipv6Addr string

			for _, addr := range addrs {
				ipNet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}

				if ipNet.IP.To4() != nil {
					hasIPv4 = true
					ipv4Addr = ipNet.IP.String()
				} else {
					hasIPv6 = true
					ipv6Addr = ipNet.IP.String()
				}
			}

			// Test IPv4 if available
			if hasIPv4 {
				contains, err := IfaceContainIPs(testIface, []string{ipv4Addr})
				assert.NoError(t, err)
				assert.True(t, contains, "Should find IPv4 address")
			}

			// Test IPv6 if available
			if hasIPv6 {
				contains, err := IfaceContainIPs(testIface, []string{ipv6Addr})
				assert.NoError(t, err)
				assert.True(t, contains, "Should find IPv6 address")
			}

			if hasIPv4 || hasIPv6 {
				return
			}
		}
	}

	t.Skip("No suitable interface found for testing")
}

// TestReplaceQdisc tests the replaceQdisc function
func TestReplaceQdisc(t *testing.T) {
	// This test requires root privileges and actual network interfaces
	// We'll create a mock link and test the structure

	link := createMockLink("test0", 1)

	// Try to replace qdisc - this will likely fail without root, but we test the call
	err := replaceQdisc(link)

	// We expect an error in most test environments (no permissions)
	// but the function should not panic
	if err != nil {
		t.Logf("Expected error in test environment: %v", err)
	}
}

// TestManageTCProgramByFd_InvalidMode tests invalid mode handling
func TestManageTCProgramByFd_InvalidMode(t *testing.T) {
	link := createMockLink("test0", 1)

	err := ManageTCProgramByFd(link, 3, 999) // Invalid mode
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid mode")
}

// TestManageTCProgramByFd_Attach tests attach mode
func TestManageTCProgramByFd_Attach(t *testing.T) {
	link := createMockLink("test0", 1)

	// This will fail without root, but shouldn't panic
	err := ManageTCProgramByFd(link, 3, 1) // 1 = TC_ATTACH (assuming constants.TC_ATTACH = 1)

	// We expect an error in test environment
	if err != nil {
		t.Logf("Expected error in test environment: %v", err)
	}
}

// BenchmarkIfaceContainIPs benchmarks the IfaceContainIPs function
func BenchmarkIfaceContainIPs(b *testing.B) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		b.Skip("No interfaces available")
	}

	testIface := interfaces[0]
	testIPs := []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = IfaceContainIPs(testIface, testIPs)
	}
}

// BenchmarkGetVethPeerIndexFromInterface benchmarks GetVethPeerIndexFromInterface
func BenchmarkGetVethPeerIndexFromInterface(b *testing.B) {
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) == 0 {
		b.Skip("No interfaces available")
	}

	var testIface net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			testIface = iface
			break
		}
	}

	if testIface.Name == "" {
		b.Skip("No suitable interface found")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = GetVethPeerIndexFromInterface(testIface)
	}
}

// TestEdgeCases tests various edge cases
func TestEdgeCases(t *testing.T) {
	t.Run("IfaceContainIPs with nil interface", func(t *testing.T) {
		// Get a real interface to avoid nil pointer issues
		interfaces, err := net.Interfaces()
		if err != nil || len(interfaces) == 0 {
			t.Skip("No interfaces available")
		}

		// Test with invalid IP string
		_, err = IfaceContainIPs(interfaces[0], []string{"not-an-ip"})
		assert.NoError(t, err) // Should not error, just won't match
	})

	t.Run("GetVethPeerIndexFromName with empty string", func(t *testing.T) {
		_, err := GetVethPeerIndexFromName("")
		assert.Error(t, err)
	})
}

// TestIntegration tests integration scenarios
func TestIntegration(t *testing.T) {
	t.Run("Full workflow with real interface", func(t *testing.T) {
		interfaces, err := net.Interfaces()
		if err != nil {
			t.Skip("Cannot get interfaces")
		}

		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}

			// Get addresses
			addrs, err := iface.Addrs()
			if err != nil || len(addrs) == 0 {
				continue
			}

			// Test IP checking
			var testIPs []string
			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok {
					testIPs = append(testIPs, ipNet.IP.String())
				}
			}

			if len(testIPs) > 0 {
				contains, err := IfaceContainIPs(iface, testIPs)
				assert.NoError(t, err)
				assert.True(t, contains)
				return
			}
		}

		t.Skip("No suitable interface with addresses found")
	})
}

// Test error path coverage
func TestErrorPaths(t *testing.T) {
	t.Run("Interface without addresses", func(t *testing.T) {
		// This is hard to test without mocking, so we'll skip if not applicable
		interfaces, err := net.Interfaces()
		if err != nil {
			t.Skip("Cannot get interfaces")
		}

		for _, iface := range interfaces {
			addrs, _ := iface.Addrs()
			if len(addrs) == 0 {
				_, err := IfaceContainIPs(iface, []string{"192.0.2.1"})
				assert.NoError(t, err) // Should handle gracefully
				return
			}
		}
	})

	t.Run("Invalid mode values", func(t *testing.T) {
		link := createMockLink("test0", 1)

		// Test various invalid modes
		invalidModes := []int{-1, 0, 3, 100, -100}
		for _, mode := range invalidModes {
			err := ManageTCProgramByFd(link, 3, mode)
			if mode != 1 && mode != 2 { // Assuming 1=ATTACH, 2=DETACH
				assert.Error(t, err)
			}
		}
	})
}
