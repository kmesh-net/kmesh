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

package dns

import (
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

type fakeDNSServer struct {
	*dns.Server
	ttl     uint32
	failure bool

	mu sync.Mutex
	// map fqdn hostname -> ip suffix
	hosts map[string]int
}

func NewFakeDNSServer() *fakeDNSServer {
	var wg sync.WaitGroup
	wg.Add(1)
	s := &fakeDNSServer{
		Server: &dns.Server{Addr: ":0", Net: "udp", NotifyStartedFunc: wg.Done},
		hosts:  make(map[string]int),
		// default ttl is 20
		ttl: uint32(20),
	}
	s.Handler = s

	go func() {
		if err := s.ListenAndServe(); err != nil {
			log.Errorf("fake dns server error: %v", err)
		}
	}()
	wg.Wait()
	return s
}

func (s *fakeDNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	s.mu.Lock()
	defer s.mu.Unlock()

	msg := (&dns.Msg{}).SetReply(r)
	if s.failure {
		msg.Rcode = dns.RcodeServerFailure
	} else {
		domain := msg.Question[0].Name
		c, ok := s.hosts[domain]
		if ok {
			switch r.Question[0].Qtype {
			case dns.TypeA:
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: s.ttl},
					A:   net.ParseIP(fmt.Sprintf("10.0.0.%d", c)),
				})
			case dns.TypeAAAA:
				// set a long TTL for AAAA
				msg.Answer = append(msg.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: s.ttl * 10},
					AAAA: net.ParseIP(fmt.Sprintf("fd00::%x", c)),
				})
			// simulate behavior of some public/cloud DNS like Cloudflare or DigitalOcean
			case dns.TypeANY:
				msg.Rcode = dns.RcodeRefused
			default:
				msg.Rcode = dns.RcodeNotImplemented
			}
		} else {
			msg.Rcode = dns.RcodeNameError
		}
	}
	if err := w.WriteMsg(msg); err != nil {
		log.Errorf("failed writing fake DNS response: %v", err)
	}
}

func (s *fakeDNSServer) SetHosts(domain string, surfix int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hosts[dns.Fqdn(domain)] = surfix
}

func (s *fakeDNSServer) SetTTL(ttl uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ttl = ttl
}

func (r *DNSResolver) GetDNSAddresses(domain string) []string {
	r.Lock()
	defer r.Unlock()
	if entry, ok := r.cache[domain]; ok {
		return entry.Addresses
	}
	return nil
}
