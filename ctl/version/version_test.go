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

package version

import "testing"

func Test_stringMatch(t *testing.T) {
	type args struct {
		str string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{
			name: "normal test",
			args: args{
				str: "v1.1.0",
			},
			want: true,
		},
		{
			name: "alpha-version",
			args: args{
				str: "v1.1.0-alpha",
			},
			want: true,
		},
		{
			name: "failed example",
			args: args{
				str: "7.8.5",
			},
			want: false,
		},
		{
			name: "alpha.0 Suffix",
			args: args{
				str: "v1.1.1-alpha.0",
			},
			want: true,
		},
		{
			name: "alpha.bate suffix",
			args: args{
				str: "v1.1.1-alpha.beta",
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stringMatch(tt.args.str); got != tt.want {
				t.Errorf("stringMatch() = %v, want %v", got, tt.want)
			}
		})
	}
}
