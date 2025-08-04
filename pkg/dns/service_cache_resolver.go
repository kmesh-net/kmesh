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
	"strings"

	"github.com/miekg/dns"
	"kmesh.net/kmesh/pkg/controller/workload/cache"
)

func NewServiceCacheResolver(cache cache.ServiceCache) *serviceCacheResolver {
	return &serviceCacheResolver{
		cache: cache,
	}
}

type serviceCacheResolver struct {
	cache cache.ServiceCache
}

func (s *serviceCacheResolver) Resolve(req *dns.Msg) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	for _, q := range req.Question {
		log.Infof("received query for: %s, type: %s", q.Name, dns.TypeToString[q.Qtype])

		hostname := strings.TrimSuffix(q.Name, ".")
		svc := s.cache.GetServiceByHost(hostname)

		if svc == nil {
			log.Infof("service not found for: %s", q.Name)
			continue
		}

		if len(svc.GetAddresses()) == 0 {
			log.Infof("no addresses found for: %s", q.Name)
			continue
		}

		switch q.Qtype {
		case dns.TypeA:
			ip := net.IP(svc.GetAddresses()[0].Address)
			if ip == nil || ip.To4() == nil {
				log.Errorf("invalid IPv4 address in records for %s: %s", q.Name, ip.String())
				continue
			}

			rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip.String()))
			if err != nil {
				log.Errorf("error creating A record: %v", err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		case dns.TypeAAAA:
			if len(svc.GetAddresses()) < 2 {
				log.Infof("no ipv6 address found")
				continue
			}
			ip := net.IP(svc.GetAddresses()[1].Address)
			if ip == nil || ip.To16() == nil {
				log.Errorf("invalid IP address: %s", ip.String())
				continue
			}

			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN AAAA %s", q.Name, 60, ip.String()))
			if err != nil {
				log.Errorf("error creating AAAA record: %v", err)
				continue
			}
			m.Answer = append(m.Answer, rr)
		}
	}

	if len(m.Answer) == 0 {
		m.SetRcode(req, dns.RcodeNameError)
	}

	return m, nil
}
