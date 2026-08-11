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
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDomainTableBasicOps(t *testing.T) {
	table := NewDomainTable()

	ip1 := table.Add("Example.com.")
	require.True(t, ip1.IsValid())

	ip2 := table.Add("example.com")
	assert.Equal(t, ip1, ip2, "add should be idempotent")

	got, ok := table.Lookup("EXAMPLE.COM.")
	require.True(t, ok)
	assert.Equal(t, ip1, got, "lookup should normalize trailing dot and case")

	ip3 := table.Add("other.example.com")
	require.True(t, ip3.IsValid())
	assert.NotEqual(t, ip1, ip3, "different hosts should get different synthetic IPs")

	table.Remove("example.com.")
	_, ok = table.Lookup("example.com")
	assert.False(t, ok)
}

func TestProxyReturnsSyntheticRecord(t *testing.T) {
	table := NewDomainTable()
	syntheticIP := table.Add("synthetic.example.com")
	require.True(t, syntheticIP.IsValid())

	p, err := NewProxy("127.0.0.1:0", table, []string{"127.0.0.1:1"})
	require.NoError(t, err)

	go func() {
		_ = p.Start()
	}()
	require.Eventually(t, func() bool {
		return p.server.PacketConn != nil
	}, time.Second, 10*time.Millisecond)
	defer func() {
		_ = p.Close()
	}()

	req := new(dns.Msg)
	req.SetQuestion("synthetic.example.com.", dns.TypeA)

	resp, _, err := (&dns.Client{Net: "udp"}).Exchange(req, p.Addr())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, net.IP(syntheticIP.AsSlice()).String(), a.A.String())
	assert.Equal(t, uint32(30), a.Hdr.Ttl)
}

func TestProxyForwardsUnknownHost(t *testing.T) {
	upstream := NewFakeDNSServer()
	upstream.SetHosts("forward.example.com", 9)
	defer func() {
		_ = upstream.Shutdown()
	}()

	p, err := NewProxy("127.0.0.1:0", NewDomainTable(), []string{upstream.Server.PacketConn.LocalAddr().String()})
	require.NoError(t, err)

	go func() {
		_ = p.Start()
	}()
	require.Eventually(t, func() bool {
		return p.server.PacketConn != nil
	}, time.Second, 10*time.Millisecond)
	defer func() {
		_ = p.Close()
	}()

	req := new(dns.Msg)
	req.SetQuestion("forward.example.com.", dns.TypeA)

	resp, _, err := (&dns.Client{Net: "udp"}).Exchange(req, p.Addr())
	require.NoError(t, err)
	require.Equal(t, dns.RcodeSuccess, resp.Rcode)
	require.Len(t, resp.Answer, 1)

	a, ok := resp.Answer[0].(*dns.A)
	require.True(t, ok)
	assert.Equal(t, "10.0.0.9", a.A.String())
}
