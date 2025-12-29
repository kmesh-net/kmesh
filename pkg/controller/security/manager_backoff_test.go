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

package security

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	istiosecurity "istio.io/istio/pkg/security"
)

// MockCaClient simulates the CA behavior
type MockCaClient struct {
	Fail       bool
	FetchCount int
	mu         sync.Mutex
}

func (m *MockCaClient) CsrSend(csrPEM []byte, certValidsec int64, identity string) ([]string, error) {
	return nil, nil
}

func (m *MockCaClient) FetchCert(identity string) (*istiosecurity.SecretItem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.FetchCount++

	if m.Fail {
		return nil, errors.New("simulated CA connection error")
	}
	return &istiosecurity.SecretItem{
		ResourceName: identity,
		ExpireTime:   time.Now().Add(24 * time.Hour),
	}, nil
}

func (m *MockCaClient) Close() error { return nil }

type mockQueue struct{}

func (m *mockQueue) Add(item any)                              {}
func (m *mockQueue) Len() int                                  { return 0 }
func (m *mockQueue) Get() (item any, shutdown bool)            { return nil, true }
func (m *mockQueue) Done(item any)                             {}
func (m *mockQueue) ShutDown()                                 {}
func (m *mockQueue) ShuttingDown() bool                        { return false }
func (m *mockQueue) AddAfter(item any, duration time.Duration) {}
func (m *mockQueue) ShutDownWithDrain()                        {}

func TestBackoff(t *testing.T) {
	t.Run("TestBackoffCalculation", func(t *testing.T) {
		runTestBackoffCalculation(t)
	})
	t.Run("TestFetchCert_RetryBehavior", func(t *testing.T) {
		runTestFetchCertRetryBehavior(t)
	})
}

func runTestBackoffCalculation(t *testing.T) {
	originalBase := baseRetryInterval
	defer func() { baseRetryInterval = originalBase }()
	baseRetryInterval = 100 * time.Millisecond

	sm := &SecretManager{
		certsCache: newCertCache(),
	}
	identity := "spiffe://test/jitter"
	sm.certsCache.addOrUpdate(identity)

	delay1 := sm.handleFetchError(identity, errors.New("test"))
	delay2 := sm.handleFetchError(identity, errors.New("test"))

	assert.Greater(t, delay1, time.Duration(0), "Delay should be positive")
	assert.Greater(t, delay2, time.Duration(0), "Delay should be positive")
}

func runTestFetchCertRetryBehavior(t *testing.T) {
	originalBase := baseRetryInterval
	defer func() { baseRetryInterval = originalBase }()
	baseRetryInterval = 10 * time.Millisecond

	mockCA := &MockCaClient{Fail: true}
	sm := &SecretManager{
		caClient:        mockCA,
		certsCache:      newCertCache(),
		certRequestChan: make(chan certRequest, 10),
	}

	identity := "spiffe://test/retry"
	sm.certsCache.addOrUpdate(identity)

	sm.fetchCert(identity)

	select {
	case req := <-sm.certRequestChan:
		assert.Equal(t, identity, req.Identity)
		assert.Equal(t, RETRY, req.Operation)
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Expected retry request did not arrive in time")
	}
}
