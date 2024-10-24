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
	"testing"
	"time"

	v1 "github.com/cncf/xds/go/udpa/type/v1"
	listenerv3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"

	"kmesh.net/kmesh/api/v2/filter"
)

func mockFilter(maxTokens int64, tokensPerFill int64, fillInterval string) *listenerv3.Filter {
	bucket := &v1.TypedStruct{
		TypeUrl: "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
		Value: &structpb.Struct{
			Fields: map[string]*structpb.Value{
				"token_bucket": {
					Kind: &structpb.Value_StructValue{
						StructValue: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"fill_interval": {
									Kind: &structpb.Value_StringValue{StringValue: fillInterval},
								},
								"max_tokens": {
									Kind: &structpb.Value_NumberValue{NumberValue: float64(maxTokens)},
								},
								"tokens_per_fill": {
									Kind: &structpb.Value_NumberValue{NumberValue: float64(tokensPerFill)},
								},
							},
						},
					},
				},
			},
		},
	}

	typedConfig, err := anypb.New(bucket)
	if err != nil {
		panic("failed to create Any from bucket: " + err.Error())
	}

	return &listenerv3.Filter{
		ConfigType: &listenerv3.Filter_TypedConfig{
			TypedConfig: typedConfig,
		},
	}
}

func TestNewLocalRateLimit(t *testing.T) {
	tests := []struct {
		name      string
		setupFunc func() *listenerv3.Filter
		want      *filter.LocalRateLimit
		wantErr   bool
	}{
		{
			name: "valid filter, should succeed",
			setupFunc: func() *listenerv3.Filter {
				return mockFilter(10, 5, "1s")
			},
			want: &filter.LocalRateLimit{
				TokenBucket: &filter.TokenBucket{
					MaxTokens:     10,
					TokensPerFill: 5,
					FillInterval:  time.Second.Nanoseconds(),
				},
			},
			wantErr: false,
		},
		{
			name: "valid filter, should succeed",
			setupFunc: func() *listenerv3.Filter {
				return mockFilter(100, 50, "1m")
			},
			want: &filter.LocalRateLimit{
				TokenBucket: &filter.TokenBucket{
					MaxTokens:     100,
					TokensPerFill: 50,
					FillInterval:  time.Minute.Nanoseconds(),
				},
			},
			wantErr: false,
		},
		{
			name: "invalid filter fill interval, should failed",
			setupFunc: func() *listenerv3.Filter {
				return mockFilter(100, 50, "invalid")
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "invalid filter, should return nil",
			setupFunc: func() *listenerv3.Filter {
				return &listenerv3.Filter{} // Empty filter for error case
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := tt.setupFunc()
			result, err := NewLocalRateLimit(filter)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, tt.want.TokenBucket.MaxTokens, result.LocalRateLimit.TokenBucket.MaxTokens)
				assert.Equal(t, tt.want.TokenBucket.TokensPerFill, result.LocalRateLimit.TokenBucket.TokensPerFill)
				assert.Equal(t, tt.want.TokenBucket.FillInterval, result.LocalRateLimit.TokenBucket.FillInterval)
			}
		})
	}
}
