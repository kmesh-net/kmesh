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
	"sync"
	"time"

	"container/heap"

	istiosecurity "istio.io/istio/pkg/security"

	"kmesh.net/kmesh/pkg/constants"
	"kmesh.net/kmesh/pkg/logger"
)

var log = logger.NewLoggerField("security")

type certExp struct {
	identity string
	exp      time.Time
	index    int
}

type certCache struct {
	cert   *istiosecurity.SecretItem
	refCnt int32
}

type certsCache struct {
	certs map[string]*certCache
	mu    sync.Mutex
}

type securityData struct {
	Identity  string
	Operation int
}

type SecretManager struct {
	caClient *caClient

	// configOptions includes all configurable params for the cache.
	configOptions *istiosecurity.Options

	// storing certificates
	certsCache *certsCache

	// Prioritize certificates based on exp
	certsQueue *certificateQueue

	certsOpChan chan securityData
}

type certificateQueue struct {
	certs []*certExp
	mu    sync.Mutex
}

func (s *SecretManager) SendData(identity string, op int) {
	data := securityData{Identity: identity, Operation: op}
	s.certsOpChan <- data
}

func (s *SecretManager) operateCerts() {
	for data := range s.certsOpChan {
		identity, op := data.Identity, data.Operation

		switch op {
		case ApplyCert:
			go s.addCerts(identity)
		case DeleteCert:
			go s.deleteCerts(identity)
		}
	}
}

func newCertCache() *certsCache {
	return &certsCache{
		certs: make(map[string]*certCache),
		mu:    sync.Mutex{},
	}
}

func newPriorityQueue() *certificateQueue {
	return &certificateQueue{
		certs: make([]*certExp, 0),
		mu:    sync.Mutex{},
	}
}

func (pq *certificateQueue) Push(x interface{}) {
	n := len(pq.certs)
	item := x.(*certExp)
	item.index = n
	pq.certs = append(pq.certs, item)
}

func (pq *certificateQueue) Pop() interface{} {
	old := pq.certs
	n := len(old)
	x := old[n-1]
	old[n-1] = nil // avoid memory leak
	x.index = -1
	pq.certs = old[0 : n-1]
	return x
}

func (pq *certificateQueue) Len() int {
	return len(pq.certs)
}

func (pq *certificateQueue) Less(i, j int) bool {
	return pq.certs[i].exp.Before(pq.certs[j].exp)
}

func (pq *certificateQueue) Swap(i, j int) {
	pq.certs[i], pq.certs[j] = pq.certs[j], pq.certs[i]
}

func (pq *certificateQueue) addItem(certExp *certExp) {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	heap.Push(pq, certExp)
}

func (pq *certificateQueue) delete(identity string) *certExp {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	for i := 0; i < len(pq.certs); i++ {
		if pq.certs[i].identity == identity {
			return heap.Remove(pq, i).(*certExp)
		}
	}
	return nil
}

// Find the top item and pop if it is about to expire
func (pq *certificateQueue) lookupAndPop() *certExp {
	pq.mu.Lock()
	defer pq.mu.Unlock()
	top := pq.certs[0]
	if time.Until(top.exp.Add(-10*time.Minute)) <= 0 {
		return heap.Pop(pq).(*certExp)
	}
	return nil
}

func (s *SecretManager) lookupAndStoreCert(identity string, newCert *istiosecurity.SecretItem) {
	s.certsCache.mu.Lock()
	defer s.certsCache.mu.Unlock()
	// Check if the key exists in the map
	// If refCnt == 0, then this certificate is about to be deleted, so do not perform a refresh.
	certCache := s.certsCache.certs[identity]
	if certCache != nil && certCache.refCnt != 0 {
		certCache.cert = newCert
		certExp := certExp{exp: newCert.ExpireTime, identity: identity}
		s.certsQueue.addItem(&certExp)
		log.Infof("cert %v add, exp:%v\n", identity, newCert.ExpireTime)
	}
}

// Check if the certificate already exists, if it does, increment the reference count by 1,
// if it doesn't, request a new certificate.
func (c *certsCache) lookupOrStore(identity string) *certCache {
	c.mu.Lock()
	defer c.mu.Unlock()
	cert := c.certs[identity]
	if cert != nil {
		cert.refCnt++
		return cert
	}
	cert = &certCache{
		refCnt: 1,
	}
	c.certs[identity] = cert
	return nil
}

func (c *certsCache) delete(identity string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.certs, identity)
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
	certCache := newCertCache()
	pq := newPriorityQueue()
	heap.Init(pq)
	certOpChan := make(chan securityData, maxGoroutines)

	secretManager := SecretManager{
		caClient:      caClient,
		configOptions: options,
		certsCache:    certCache,
		certsQueue:    pq,
		certsOpChan:   certOpChan,
	}
	go secretManager.operateCerts()
	go secretManager.refreshExpiringCerts()
	return &secretManager, nil
}

// Automatically check and refresh when the validity period expires
// Store the identity in the priority queue according to the expiration time.
// Check the highest priority element in the queue every 5 minutes.
// If it is about to expire, pop up the element and reapply for the certificate.
func (s *SecretManager) refreshExpiringCerts() {
	for {
		if s.certsQueue.Len() != 0 {
			// As long as the memory in the Go language is referenced by any pointer,
			// it will not be released. The map stores pointers, so it is safe here.
			top := s.certsQueue.lookupAndPop()
			if top != nil {
				log.Debugf("refresh identity: %v  exp: %v\n", top.identity, top.exp)
				newCert, err := s.caClient.fetchCert(top.identity)
				if err != nil {
					log.Errorf("%v refresh fetchCert error : %v", top.identity, err)
					return
				}
				s.lookupAndStoreCert(top.identity, newCert)
				continue
			}
		}
		time.Sleep(5 * time.Minute)
	}
}

// Initialize the certificate for the first time
func (s *SecretManager) addCerts(identity string) {
	certificate := s.certsCache.lookupOrStore(identity)
	if certificate != nil {
		log.Debugf("identity: %v refCnt++ : %v\n", identity, certificate.refCnt)
		return
	}

	newCert, err := s.caClient.fetchCert(identity)
	if err != nil {
		log.Errorf("%v fetcheCert error: %v", identity, err)
		s.certsCache.delete(identity)
		return
	}

	// Save the new certificate in the map and add a record to the priority queue
	// of the auto-refresh task when it expires
	s.lookupAndStoreCert(identity, newCert)
}

// Set the removed to true for the items in the certsQueue priority queue.
// Delete the certificate and status map corresponding to the identity.
func (s *SecretManager) deleteCerts(identity string) {
	s.certsCache.mu.Lock()
	defer s.certsCache.mu.Unlock()
	certificate := s.certsCache.certs[identity]
	if certificate == nil {
		return
	}
	certificate.refCnt--
	log.Debugf("identity: %v refCnt-- : %v\n", identity, certificate.refCnt)
	if certificate.refCnt == 0 {
		delete(s.certsCache.certs, identity)
		s.certsQueue.delete(identity)
		log.Debugf("identity: %v cert deleted\n", identity)
	}
}
