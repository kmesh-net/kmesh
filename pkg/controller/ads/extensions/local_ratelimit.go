//go:build feature_ratelimit
// +build feature_ratelimit

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
package extensions

import (
	"fmt"
	"time"

	v1 "github.com/cncf/xds/go/udpa/type/v1"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"kmesh.net/kmesh/api/v2/filter"
	"kmesh.net/kmesh/api/v2/listener"
)

const LocalRateLimit = "envoy.filters.tcp.local_ratelimit"

// NewLocalRateLimit constructs a new LocalRateLimit filter wrapper.
func NewLocalRateLimit(filter *listenerv3.Filter) (*listener.Filter_LocalRateLimit, error) {
	localRateLimit, err := newLocalRateLimit(filter)
	if err != nil {
		return nil, err
	}

	return &listener.Filter_LocalRateLimit{
		LocalRateLimit: localRateLimit,
	}, nil
}

// newLocalRateLimit creates a new LocalRateLimit filter.
func newLocalRateLimit(Filter *listenerv3.Filter) (*filter.LocalRateLimit, error) {
	unstructured, err := unmarshalToTypedStruct(Filter)
	if err != nil {
		return nil, err
	}

	bucket := unstructured.GetValue().GetFields()["token_bucket"].GetStructValue().GetFields()
	interval, err := time.ParseDuration(bucket["fill_interval"].GetStringValue())
	if err != nil {
		return nil, fmt.Errorf("failed to convert fill_interval, err: %w", err)
	}
	return &filter.LocalRateLimit{TokenBucket: &filter.TokenBucket{
		MaxTokens:     int64(bucket["max_tokens"].GetNumberValue()),
		TokensPerFill: int64(bucket["tokens_per_fill"].GetNumberValue()),
		FillInterval:  interval.Nanoseconds(),
	}}, nil
}

// unmarshalToTypedStruct unmarshal a protobuf Any message to a TypedStruct.
func unmarshalToTypedStruct(filter *listenerv3.Filter) (*v1.TypedStruct, error) {
	typed := &v1.TypedStruct{}
	if err := anypb.UnmarshalTo(filter.GetTypedConfig(), typed, proto.UnmarshalOptions{}); err != nil {
		return nil, fmt.Errorf("failed to unmarshal TypedConfig %w", err)
	}
	return typed, nil
}
