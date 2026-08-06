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

package authz

import "testing"

func Test_shouldExitWithError(t *testing.T) {
	type args struct {
		failedCount    int
		totalRequested int
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "all pods failed",
			args: args{
				failedCount:    2,
				totalRequested: 2,
			},
			want: true,
		},
		{
			name: "partial success",
			args: args{
				failedCount:    1,
				totalRequested: 2,
			},
			want: false,
		},
		{
			name: "all succeeded",
			args: args{
				failedCount:    0,
				totalRequested: 2,
			},
			want: false,
		},
		{
			name: "no pods requested",
			args: args{
				failedCount:    0,
				totalRequested: 0,
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldExitWithError(tt.args.failedCount, tt.args.totalRequested); got != tt.want {
				t.Errorf("shouldExitWithError() = %v, want %v", got, tt.want)
			}
		})
	}
}