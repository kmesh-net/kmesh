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
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	defaultSyntheticPrefixHigh = 240
	defaultSyntheticPrefixLow  = 240
	defaultProxyTTL            = uint32(30)
)

type DomainTable struct {
	mu       sync.RWMutex
	hostToIP map[string]netip.Addr
	ipToHost map[netip.Addr]string
	nextHost uint16
}

func NewDomainTable() *DomainTable {
	return &DomainTable{
		hostToIP: make(map[string]netip.Addr),
		ipToHost: make(map[netip.Addr]string),
		nextHost: 1,
	}
}

func (d *DomainTable) Add(host string) netip.Addr {
	key := normalizeHost(host)
	if key == "" {
		return netip.Addr{}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if ip, ok := d.hostToIP[key]; ok {
		return ip
	}

	for i := 0; i < 0xffff; i++ {
		ip := syntheticIPv4FromHost(d.nextHost)
		d.nextHost++
		if d.nextHost == 0 {
			d.nextHost = 1
		}
		if _, used := d.ipToHost[ip]; used {
			continue
		}
		d.hostToIP[key] = ip
		d.ipToHost[ip] = key
		return ip
	}

	return netip.Addr{}
}

func (d *DomainTable) Lookup(host string) (netip.Addr, bool) {
	key := normalizeHost(host)
	if key == "" {
		return netip.Addr{}, false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()
	ip, ok := d.hostToIP[key]
	return ip, ok
}

func (d *DomainTable) Remove(host string) {
	key := normalizeHost(host)
	if key == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	ip, ok := d.hostToIP[key]
	if !ok {
		return
	}
	delete(d.hostToIP, key)
	delete(d.ipToHost, ip)
}

func (d *DomainTable) Snapshot() map[string]netip.Addr {
	d.mu.RLock()
	defer d.mu.RUnlock()

	out := make(map[string]netip.Addr, len(d.hostToIP))
	for k, v := range d.hostToIP {
		out[k] = v
	}
	return out
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func syntheticIPv4FromHost(host uint16) netip.Addr {
	return netip.AddrFrom4([4]byte{
		defaultSyntheticPrefixHigh,
		defaultSyntheticPrefixLow,
		byte(host >> 8),
		byte(host),
	})
}

type Proxy struct {
	server    *dns.Server
	table     *DomainTable
	upstreams []string
	ttl       uint32
	client    *dns.Client
}

func NewProxy(addr string, table *DomainTable, upstreams []string) (*Proxy, error) {
	if table == nil {
		table = NewDomainTable()
	}

	if len(upstreams) == 0 {
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		upstreams = make([]string, 0, len(config.Servers))
		for _, server := range config.Servers {
			upstreams = append(upstreams, netJoinHostPort(server, config.Port))
		}
	}

	p := &Proxy{
		table:     table,
		upstreams: upstreams,
		ttl:       defaultProxyTTL,
		client: &dns.Client{
			Net:          "udp",
			DialTimeout:  5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
	}
	p.server = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: p,
	}

	return p, nil
}

func (p *Proxy) Start() error {
	return p.server.ListenAndServe()
}

func (p *Proxy) Close() error {
	return p.server.Shutdown()
}

func (p *Proxy) Addr() string {
	if p.server.PacketConn != nil {
		return p.server.PacketConn.LocalAddr().String()
	}
	return p.server.Addr
}

func (p *Proxy) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	if req == nil {
		msg := new(dns.Msg)
		msg.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(msg)
		return
	}

	if len(req.Question) == 0 {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(msg)
		return
	}

	question := req.Question[0]
	if question.Qtype == dns.TypeA {
		if ip, ok := p.table.Lookup(question.Name); ok {
			reply := new(dns.Msg)
			reply.SetReply(req)
			reply.Authoritative = true
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    p.ttl,
				},
				A: ip.AsSlice(),
			})
			_ = w.WriteMsg(reply)
			return
		}
	}

	for _, upstream := range p.upstreams {
		resp, _, err := p.client.Exchange(req, upstream)
		if err != nil || resp == nil {
			continue
		}
		_ = w.WriteMsg(resp)
		return
	}

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Rcode = dns.RcodeServerFailure
	_ = w.WriteMsg(msg)
}

func netJoinHostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}
