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
	"time"

	"github.com/miekg/dns"
)

type upstreamResolver struct {
	*dns.Client
	upstreams []string
}

func NewUpstreamResolver(upstreams ...string) *upstreamResolver {
	return &upstreamResolver{
		upstreams: upstreams,
		Client: &dns.Client{
			DialTimeout:  5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
	}
}

func (r *upstreamResolver) WithUpstreams(upstreams ...string) *upstreamResolver {
	r.upstreams = append(r.upstreams, upstreams...)
	return r
}

func (r *upstreamResolver) Resolve(req *dns.Msg) (*dns.Msg, error) {
	var response *dns.Msg

	for _, upstream := range r.upstreams {
		resp, _, err := r.Exchange(req, upstream)
		if err != nil || resp == nil {
			continue
		}

		response = resp
		if resp.Rcode == dns.RcodeSuccess {
			break
		}
	}

	if response == nil {
		response = new(dns.Msg)
		response.SetReply(req)
		response.Rcode = dns.RcodeServerFailure
	}

	return response, nil
}
