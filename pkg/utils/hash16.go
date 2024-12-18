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

type Sum uint16

func (s *Sum) Write(input []byte) (n int, err error) {
	var sum uint64 = 0
	for pos, i := range input {
		si := uint32(i)
		switch pos % 4 {
		case 0:
		case 1:
			si = si << 8
		case 2:
			si = si << 16
		case 3:
			si = si << 24
		}
		sum += uint64(si)
	}
	for sum&0xffffffffffff0000 != 0 {
		sum = sum&0xffff + sum>>16
	}
	*s = Sum(sum)
	return len(input), nil
}

func (s *Sum) Sum16() uint16 {
	return uint16(*s)
}
