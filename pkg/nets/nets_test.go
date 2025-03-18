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

package nets

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ConvertIpToUint32(t *testing.T) {
	ip := "192.168.0.1"
	val := ConvertIpToUint32(ip)
	assert.Equal(t, uint32(0x100a8c0), val)

	// It can not panic even for invalid ip
	val = ConvertIpToUint32("a.b.c.d")
	assert.Equal(t, uint32(0), val)
}

func TestCopyIpByteFromSlice(t *testing.T) {
	v6addr, _ := netip.ParseAddr("2001::1")
	v6Slices := v6addr.AsSlice()
	testcases := []struct {
		name     string
		input    []byte
		expected [16]byte
	}{
		{
			name:     "ipv4",
			input:    []byte{192, 168, 1, 1},
			expected: [16]byte{192, 168, 1, 1},
		},
		{
			name:     "ipv6",
			input:    v6Slices,
			expected: [16]byte{0x20, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1},
		},
		{
			name:     "invalid",
			input:    []byte{192, 168, 1, 1, 1, 1},
			expected: [16]byte{},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			var out [16]byte

			CopyIpByteFromSlice(&out, tc.input)
			assert.Equal(t, tc.expected, out)
		})
	}
}

func TestCompareIpByte(t *testing.T) {
	type args struct {
		newData [][]byte
		oldData [][]byte
	}
	tests := []struct {
		name string
		args args
		want [][]byte
	}{
		{
			name: "Ipv4 compare test",
			args: args{
				newData: [][]byte{
					{1, 1, 1, 1},
					{2, 2, 2, 2},
				},
				oldData: [][]byte{
					{3, 3, 3, 3},
					{2, 2, 2, 2},
				},
			},
			want: [][]byte{
				{3, 3, 3, 3},
			},
		},
		{
			name: "Ipv6 compare test",
			args: args{
				newData: [][]byte{
					{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
					{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				},
				oldData: [][]byte{
					{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
					{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2},
				},
			},
			want: [][]byte{
				{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CompareIpByte(tt.args.newData, tt.args.oldData)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestConvertPortToLittleEndian(t *testing.T) {
	tests := []struct {
		input    uint32
		expected uint32
	}{
		{8080, 8080},
		{0x5678, 0x5678},
	}

	for _, test := range tests {
		input := ConvertPortToBigEndian(test.input)
		actual := ConvertPortToLittleEndian(input)
		if actual != test.expected {
			t.Errorf("ConvertPortToLittleEndian(%#x) = %#x; expected %#x", test.input, actual, test.expected)
		}
	}
}

func TestIpString(t *testing.T) {
	tests := []struct {
		ip       [16]byte
		expected string
	}{
		{[16]byte{192, 168, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "192.168.0.1"},
		{[16]byte{192, 168, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, "c0a8:1::1"},
		{[16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, "0.0.0.0"},
	}

	for _, test := range tests {
		actual := IpString(test.ip)
		if actual != test.expected {
			t.Errorf("IpString(%v) = %v; expected %v", test.ip, actual, test.expected)
		}
	}
}
