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

package utils

import (
	"testing"
)

func TestIsVersionLowerThan(t *testing.T) {
	tests := []struct {
		name          string
		kernelVersion string
		major         int
		minor         int
		want          bool
	}{
		{
			name:          "lower major version",
			kernelVersion: "4.15.0",
			major:         5,
			minor:         13,
			want:          true,
		},
		{
			name:          "higher major version",
			kernelVersion: "6.0.0",
			major:         5,
			minor:         13,
			want:          false,
		},
		{
			name:          "same major, lower minor version",
			kernelVersion: "5.10.0",
			major:         5,
			minor:         13,
			want:          true,
		},
		{
			name:          "same major, same minor version",
			kernelVersion: "5.13.0",
			major:         5,
			minor:         13,
			want:          false,
		},
		{
			name:          "same major, higher minor version",
			kernelVersion: "5.15.0",
			major:         5,
			minor:         13,
			want:          false,
		},
		{
			name:          "invalid version format - single number",
			kernelVersion: "5",
			major:         5,
			minor:         13,
			want:          true,
		},
		{
			name:          "invalid version format - non-numeric",
			kernelVersion: "abc.def",
			major:         5,
			minor:         13,
			want:          true,
		},
		{
			name:          "empty version string",
			kernelVersion: "",
			major:         5,
			minor:         13,
			want:          true,
		},
		{
			name:          "complex version string (Ubuntu style)",
			kernelVersion: "5.15.0-101-generic",
			major:         5,
			minor:         13,
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isVersionLowerThan(tt.kernelVersion, tt.major, tt.minor); got != tt.want {
				t.Errorf("isVersionLowerThan(%v, %v, %v) = %v, want %v", tt.kernelVersion, tt.major, tt.minor, got, tt.want)
			}
		})
	}
}

func TestInt8ToStr(t *testing.T) {
	tests := []struct {
		name string
		arr  []int8
		want string
	}{
		{
			name: "normal string",
			arr:  []int8{104, 101, 108, 108, 111, 0}, // "hello"
			want: "hello",
		},
		{
			name: "empty string",
			arr:  []int8{0},
			want: "",
		},
		{
			name: "string without null terminator",
			arr:  []int8{97, 98, 99}, // "abc"
			want: "abc",
		},
		{
			name: "string with multiple null terminators",
			arr:  []int8{102, 111, 111, 0, 98, 97, 114, 0}, // "foo\0bar\0"
			want: "foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := int8ToStr(tt.arr); got != tt.want {
				t.Errorf("int8ToStr() = %v, want %v", got, tt.want)
			}
		})
	}
}
