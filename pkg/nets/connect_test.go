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

package nets

import (
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	istiogrpc "istio.io/istio/pilot/pkg/grpc"
	"istio.io/istio/pkg/keepalive"
	"istio.io/istio/pkg/security"
)

// Save original functions to restore after each test
var (
	origClientOptionsProvider func(*keepalive.Options, *istiogrpc.TLSOptions) ([]grpc.DialOption, error)
	origNewCredFetcher        func(string, string, string, string) (security.CredFetcher, error)
	origGrpcDial              func(string, ...grpc.DialOption) (*grpc.ClientConn, error)
)

func init() {
	origClientOptionsProvider = clientOptionsProvider
	origNewCredFetcher = newCredFetcher
	origGrpcDial = grpcDial
}

// Helper function to reset mocks after each test
func resetMocks() {
	clientOptionsProvider = origClientOptionsProvider
	newCredFetcher = origNewCredFetcher
	grpcDial = origGrpcDial
}

func TestGrpcConnect_Success(t *testing.T) {
	defer resetMocks()

	clientOptionsProvider = func(
		opts *keepalive.Options,
		tls *istiogrpc.TLSOptions,
	) ([]grpc.DialOption, error) {
		return []grpc.DialOption{}, nil
	}

	newCredFetcher = func(
		credType, trustDomain, jwt, idp string,
	) (security.CredFetcher, error) {
		return &mockCredFetcher{}, nil
	}

	grpcDial = func(addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return &grpc.ClientConn{}, nil
	}

	conn, err := GrpcConnect("127.0.0.1:8080")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Error("expected non-nil connection")
	}
}

func TestGrpcConnect_ClientOptionsError(t *testing.T) {
	defer resetMocks()

	clientOptionsProvider = func(
		opts *keepalive.Options,
		tls *istiogrpc.TLSOptions,
	) ([]grpc.DialOption, error) {
		return nil, errors.New("client options error")
	}

	_, err := GrpcConnect("127.0.0.1:8080")
	if err == nil {
		t.Error("expected error, got nil")
	}
	if err.Error() != "client options error" {
		t.Errorf("expected 'client options error', got '%v'", err)
	}
}

func TestGrpcConnect_CredFetcherError(t *testing.T) {
	defer resetMocks()

	clientOptionsProvider = func(
		opts *keepalive.Options,
		tls *istiogrpc.TLSOptions,
	) ([]grpc.DialOption, error) {
		return []grpc.DialOption{}, nil
	}

	newCredFetcher = func(
		credType, trustDomain, jwt, idp string,
	) (security.CredFetcher, error) {
		return nil, errors.New("cred fetch error")
	}

	_, err := GrpcConnect("127.0.0.1:8080")
	if err == nil {
		t.Error("expected error, got nil")
	}
	if err.Error() != "cred fetch error" {
		t.Errorf("expected 'cred fetch error', got '%v'", err)
	}
}

func TestGrpcConnect_DialError(t *testing.T) {
	defer resetMocks()

	clientOptionsProvider = func(
		opts *keepalive.Options,
		tls *istiogrpc.TLSOptions,
	) ([]grpc.DialOption, error) {
		return []grpc.DialOption{}, nil
	}

	newCredFetcher = func(
		credType, trustDomain, jwt, idp string,
	) (security.CredFetcher, error) {
		return &mockCredFetcher{}, nil
	}

	grpcDial = func(addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return nil, errors.New("dial error")
	}

	_, err := GrpcConnect("127.0.0.1:8080")
	if err == nil {
		t.Error("expected dial error, got nil")
	}
	if err.Error() != "dial error" {
		t.Errorf("expected 'dial error', got '%v'", err)
	}
}

func TestGrpcConnect_EmptyAddress(t *testing.T) {
	defer resetMocks()

	clientOptionsProvider = func(
		opts *keepalive.Options,
		tls *istiogrpc.TLSOptions,
	) ([]grpc.DialOption, error) {
		return []grpc.DialOption{}, nil
	}

	newCredFetcher = func(
		credType, trustDomain, jwt, idp string,
	) (security.CredFetcher, error) {
		return &mockCredFetcher{}, nil
	}

	grpcDial = func(addr string, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
		return &grpc.ClientConn{}, nil
	}

	conn, err := GrpcConnect("")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if conn == nil {
		t.Error("expected non-nil connection")
	}
}

func TestCalculateInterval_InitialValue(t *testing.T) {
	result := CalculateInterval(0)
	expected := MaxRetryInterval / MaxRetryCount
	if result != expected {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestCalculateInterval_BelowMax(t *testing.T) {
	input := time.Second * 5
	result := CalculateInterval(input)
	expected := input + MaxRetryInterval/MaxRetryCount
	if result != expected {
		t.Errorf("expected %v, got %v", expected, result)
	}
}

func TestCalculateInterval_AtMax(t *testing.T) {
	result := CalculateInterval(MaxRetryInterval)
	if result != MaxRetryInterval {
		t.Errorf("expected %v, got %v", MaxRetryInterval, result)
	}
}

func TestCalculateInterval_ExceedsMax(t *testing.T) {
	result := CalculateInterval(MaxRetryInterval * 2)
	if result != MaxRetryInterval {
		t.Errorf("expected %v, got %v", MaxRetryInterval, result)
	}
}

func TestCalculateInterval_JustBelowMax(t *testing.T) {
	// Test a value that will exceed max after increment
	input := MaxRetryInterval - time.Second
	result := CalculateInterval(input)
	if result != MaxRetryInterval {
		t.Errorf("expected %v, got %v", MaxRetryInterval, result)
	}
}

func TestCalculateInterval_ProgressiveIncrease(t *testing.T) {
	testCases := []struct {
		name     string
		input    time.Duration
		expected time.Duration
	}{
		{
			name:     "5 seconds",
			input:    time.Second * 5,
			expected: time.Second*5 + MaxRetryInterval/MaxRetryCount,
		},
		{
			name:     "10 seconds",
			input:    time.Second * 10,
			expected: time.Second*10 + MaxRetryInterval/MaxRetryCount,
		},
		{
			name:     "20 seconds",
			input:    time.Second * 20,
			expected: time.Second*20 + MaxRetryInterval/MaxRetryCount,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := CalculateInterval(tc.input)
			if result != tc.expected {
				t.Errorf("input %v: expected %v, got %v", tc.input, tc.expected, result)
			}
		})
	}
}

func TestCalculateRandTime_BasicRange(t *testing.T) {
	r := CalculateRandTime(100)
	if r < 0 || r >= 100*time.Millisecond {
		t.Errorf("rand time out of range: %v", r)
	}
}

func TestCalculateRandTime_ValidRange(t *testing.T) {
	for i := 0; i < 100; i++ {
		r := CalculateRandTime(50)
		if r < 0 || r >= 50*time.Millisecond {
			t.Errorf("iteration %d: rand time out of range: %v", i, r)
		}
	}
}

func TestCalculateRandTime_LargeValue(t *testing.T) {
	r := CalculateRandTime(1000)
	if r < 0 || r >= 1000*time.Millisecond {
		t.Errorf("rand time out of range: %v", r)
	}
}

func TestCalculateRandTime_SmallValue(t *testing.T) {
	r := CalculateRandTime(1)
	if r < 0 || r >= 1*time.Millisecond {
		t.Errorf("rand time out of range: %v", r)
	}
}

func TestCalculateRandTime_Zero(t *testing.T) {
	r := CalculateRandTime(0)
	if r != 0 {
		t.Errorf("expected 0, got %v", r)
	}
}

func TestCalculateRandTime_NegativeValue(t *testing.T) {
	r := CalculateRandTime(-10)
	if r != 0 {
		t.Errorf("expected 0 for negative input, got %v", r)
	}
}

func TestCalculateRandTime_Distribution(t *testing.T) {
	// Test that we get different values over multiple calls
	results := make(map[time.Duration]bool)
	for i := 0; i < 50; i++ {
		r := CalculateRandTime(100)
		results[r] = true
	}
	// We should get at least some variety in values
	if len(results) < 5 {
		t.Error("expected more variety in random values")
	}
}

// Mock implementation of CredFetcher
type mockCredFetcher struct{}

func (m *mockCredFetcher) GetPlatformCredential() (string, error) {
	return "mock-credential", nil
}

func (m *mockCredFetcher) GetIdentityProvider() string {
	return "mock-provider"
}

func (m *mockCredFetcher) Stop() {
	// Mock implementation of Stop method
}
