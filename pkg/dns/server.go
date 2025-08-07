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

	"github.com/miekg/dns"
)

type DNSServer interface {
	ListenAndServe() error
}

type DNSServerOptions struct {
	resolver *DNSResolver

	tcpServer *dns.Server
	udpServer *dns.Server
}

func NewDNSServerOptions() *DNSServerOptions {
	return &DNSServerOptions{}
}

func (o *DNSServerOptions) WithDNSResolver(resolver *DNSResolver) *DNSServerOptions {
	o.resolver = resolver
	return o
}

func (o *DNSServerOptions) Complete() (DNSServer, error) {
	if o.resolver == nil {
		return nil, fmt.Errorf("resolver unset")
	}

	dns.HandleFunc(".", o.handler)
	o.tcpServer = &dns.Server{
		Addr: ":53",
		Net:  "tcp",
	}

	o.udpServer = &dns.Server{
		Addr: ":53",
		Net:  "udp",
	}

	return o, nil
}

func (o *DNSServerOptions) ListenAndServe() error {
	errChan := make(chan error)
	if o.udpServer != nil {
		go func() {
			errChan <- o.udpServer.ListenAndServe()
		}()
	}

	if o.tcpServer != nil {
		go func() {
			errChan <- o.tcpServer.ListenAndServe()
		}()
	}

	return <-errChan
}

func (o *DNSServerOptions) handler(w dns.ResponseWriter, r *dns.Msg) {
	log.Debugf("received DNS request, %+v", r)
	res := o.resolver.Query(r)
	log.Debugf("sending DNS response, %+v", res)
	if err := w.WriteMsg(res); err != nil {
		log.Errorf("failed to write response : %v", err)
	}
}
