/*
 * Copyright 2024 The Kmesh Authors.
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
	"container/heap"
	"sync"
	"time"

	istiosecurity "istio.io/istio/pkg/security"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("security")

type certExp struct {
	identity string
	exp      time.Time
}

type certItem struct {
	cert   *istiosecurity.SecretItem
	refCnt int32
}

type certsCache struct {
	certs map[string]*certItem
	mu    sync.RWMutex
}

type certRequest struct {
	Identity  string
	Operation int
}

type SecretManager struct {
	caClient *caClient

	// configOptions includes all configurable params for the cache.
	configOptions *istiosecurity.Options

	// storing certificates
	certsCache *certsCache

	// certs rotation priority queue based on exp
	certsRotateQueue *rotateQueue

	certRequestChan chan certRequest
}

type rotateQueue struct {
	certs []*certExp
	mu    sync.Mutex
}

func (s *SecretManager) SendCertRequest(identity string, op int) {
	s.certRequestChan <- certRequest{Identity: identity, Operation: op}
}

func (s *SecretManager) handleCertRequests() {
	for data := range s.certRequestChan {
		identity, op := data.Identity, data.Operation
		switch op {
		case ADD:
			certificate := s.certsCache.addOrUpdate(identity)
			if certificate != nil {
				log.Debugf("add identity: %v refCnt++ : %v\n", identity, certificate.refCnt)
				continue
			}
			// sign cert if only no cert exists for this identity
			go s.addCert(identity)
		case DELETE:
			s.deleteCert(identity)
		case Rotate:
			go s.rotateCert(identity)
		}
	}
}

func newCertCache() *certsCache {
	return &certsCache{
		certs: make(map[string]*certItem),
		mu:    sync.RWMutex{},
	}
}

func newCertRotateQueue() *rotateQueue {
	return &rotateQueue{
		certs: make([]*certExp, 0),
		mu:    sync.Mutex{},
	}
}

func (pq *rotateQueue) Push(x interface{}) {
	item := x.(*certExp)
	pq.certs = append(pq.certs, item)
}

func (pq *rotateQueue) Pop() interface{} {
	old := pq.certs
	n := len(old)
	x := old[n-1]
	old[n-1] = nil // avoid memory leak
	pq.certs = old[0 : n-1]
	return x
}

func (pq *rotateQueue) Len() int {
	return len(pq.certs)
}

func (pq *rotateQueue) Less(i, j int) bool {
	return pq.certs[i].exp.Before(pq.certs[j].exp)
}

func (pq *rotateQueue) Swap(i, j int) {
	pq.certs[i], pq.certs[j] = pq.certs[j], pq.certs[i]
}

func (pq *rotateQueue) addItem(certExp *certExp) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	heap.Push(pq, certExp)
}

func (pq *rotateQueue) delete(identity string) *certExp {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	for i := 0; i < len(pq.certs); i++ {
		if pq.certs[i].identity == identity {
			return heap.Remove(pq, i).(*certExp)
		}
	}
	return nil
}

// pop a certificate that is about to expire
func (pq *rotateQueue) pop() *certExp {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	return heap.Pop(pq).(*certExp)
}

func (s *SecretManager) storeCert(identity string, newCert *istiosecurity.SecretItem) {
	s.certsCache.mu.Lock()
	defer s.certsCache.mu.Unlock()
	// Check if the key exists in the map
	existing := s.certsCache.certs[identity]
	if existing == nil {
		// This can happen when delete immediately happens after add
		log.Debugf("%v has been deleted", identity)
		return
	}
	// if the new cert expire time is before the existing one, it means the new cert is actually signed earlier,
	// just ignore it.
	if existing.cert != nil && newCert.ExpireTime.Before(existing.cert.ExpireTime) {
		return
	}

	existing.cert = newCert
	certExp := certExp{
		exp:      newCert.ExpireTime,
		identity: identity,
	}
	// push to rotate queue
	s.certsRotateQueue.addItem(&certExp)
	log.Debugf("cert %v added to rotation queue, exp: %v\n", identity, newCert.ExpireTime)
}

// addOrUpdate checks whether the certificate already exists.
// If it exists, increment the reference count by 1,
// Otherwise, request a new certificate.
func (c *certsCache) addOrUpdate(identity string) *certItem {
	c.mu.Lock()
	defer c.mu.Unlock()
	cert := c.certs[identity]
	if cert != nil {
		cert.refCnt++
		return cert
	}
	cert = &certItem{
		refCnt: 1,
	}
	c.certs[identity] = cert
	return nil
}

// NewSecretManager creates a new secretManager.s
func NewSecretManager() (*SecretManager, error) {
	tlsOpts := &tlsOptions{
		RootCert: constants.RootCertPath,
	}

	options := NewSecurityOptions()
	caClient, err := newCaClient(options, tlsOpts)
	if err != nil {
		return nil, err
	}
	pq := newCertRotateQueue()
	heap.Init(pq)

	secretManager := SecretManager{
		caClient:         caClient,
		configOptions:    options,
		certsCache:       newCertCache(),
		certsRotateQueue: pq,
		certRequestChan:  make(chan certRequest, maxConcurrentCSR),
	}
	go secretManager.handleCertRequests()
	go secretManager.rotateCerts()
	return &secretManager, nil
}

// Automatically check and rotate when the validity period expires
func (s *SecretManager) rotateCerts() {
	for {
		if s.certsRotateQueue.Len() != 0 {
			top := s.certsRotateQueue.pop()
			time.Sleep(time.Until(top.exp.Add(-1 * time.Hour)))
			s.SendCertRequest(top.identity, Rotate)
		} else {
			time.Sleep(5 * time.Second)
		}
	}
}

// addCert signs a cert for the identity and cache it.
func (s *SecretManager) addCert(identity string) {
	newCert, err := s.caClient.fetchCert(identity)
	if err != nil {
		log.Errorf("fetcheCert %v error: %v", identity, err)
		// in case fetchCert failed, retry
		s.certRequestChan <- certRequest{Identity: identity, Operation: ADD}
		return
	}

	// Save the new certificate in the map and add a record to the priority queue
	// of the auto-refresh task when it expires
	s.storeCert(identity, newCert)
}

// Set the removed to true for the items in the certsRotateQueue priority queue.
// Delete the certificate and status map corresponding to the identity.
func (s *SecretManager) deleteCert(identity string) {
	s.certsCache.mu.Lock()
	defer s.certsCache.mu.Unlock()
	certificate := s.certsCache.certs[identity]
	if certificate == nil {
		return
	}
	certificate.refCnt--
	log.Debugf("remove identity: %v refCnt : %v", identity, certificate.refCnt)
	if certificate.refCnt == 0 {
		delete(s.certsCache.certs, identity)
		s.certsRotateQueue.delete(identity)
		log.Debugf("identity: %v cert deleted", identity)
	}
}

func (s *SecretManager) rotateCert(identity string) {
	s.certsCache.mu.RLock()
	certificate := s.certsCache.certs[identity]
	if certificate == nil {
		s.certsCache.mu.RUnlock()
		log.Debugf("identity: %v cert has been deleted", identity)
		return
	}
	s.certsCache.mu.RUnlock()

	s.addCert(identity)
}
