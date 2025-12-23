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
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

type fakeDNSClient struct {
	responses map[string]*dns.Msg
	errors    map[string]error
	calls     int
}

func (f *fakeDNSClient) Exchange(m *dns.Msg, addr string) (*dns.Msg, time.Duration, error) {
	f.calls++

	if err, ok := f.errors[addr]; ok {
		return nil, 0, err
	}
	if resp, ok := f.responses[addr]; ok {
		return resp, 0, nil
	}
	return nil, 0, errors.New("no response")
}

func TestResolve_SingleUpstreamSuccess(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Rcode = dns.RcodeSuccess

	r := NewUpstreamResolver("1.1.1.1:53")
	r.Client = &fakeDNSClient{
		responses: map[string]*dns.Msg{
			"1.1.1.1:53": resp,
		},
		errors: map[string]error{},
	}

	out, err := r.Resolve(req)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, out.Rcode)
}

func TestResolve_FallbackToSecondUpstream(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	failResp := new(dns.Msg)
	failResp.SetReply(req)
	failResp.Rcode = dns.RcodeServerFailure

	okResp := new(dns.Msg)
	okResp.SetReply(req)
	okResp.Rcode = dns.RcodeSuccess

	fake := &fakeDNSClient{
		responses: map[string]*dns.Msg{
			"1.1.1.1:53": failResp,
			"8.8.8.8:53": okResp,
		},
		errors: map[string]error{},
	}

	r := NewUpstreamResolver("1.1.1.1:53", "8.8.8.8:53")
	r.Client = fake

	out, err := r.Resolve(req)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, out.Rcode)
	assert.Equal(t, 2, fake.calls)
}

func TestResolve_AllUpstreamsFail(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	fake := &fakeDNSClient{
		responses: map[string]*dns.Msg{},
		errors: map[string]error{
			"1.1.1.1:53": errors.New("fail"),
			"8.8.8.8:53": errors.New("fail"),
		},
	}

	r := NewUpstreamResolver("1.1.1.1:53", "8.8.8.8:53")
	r.Client = fake

	out, err := r.Resolve(req)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeServerFailure, out.Rcode)
}

func TestWithUpstreams(t *testing.T) {
	r := NewUpstreamResolver("1.1.1.1:53")
	r.WithUpstreams("8.8.8.8:53", "9.9.9.9:53")
	assert.Len(t, r.upstreams, 3)
}
