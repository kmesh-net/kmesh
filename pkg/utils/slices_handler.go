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
 *
 */

package utils

import (
	"kmesh.net/kmesh/api/v2/workloadapi"
)

// Compare two slices and return the data added to a over b and the data missing from b over a.
//
// Arges:
//
//	a: new data
//	b: old data
//
// return:
//
//	    Add: the data added to a over b
//		Remove: the data missing from b over a
//
// TODO: Optimising functions to be able to handle different data types
func CompareSlices(a, b []*workloadapi.NetworkAddress) ([]*workloadapi.NetworkAddress, []*workloadapi.NetworkAddress) {
	aSet := make(map[*workloadapi.NetworkAddress]struct{})
	for _, item := range a {
		aSet[item] = struct{}{}
	}

	var aNew, bMissing []*workloadapi.NetworkAddress
	for _, item := range b {
		if _, ok := aSet[item]; !ok {
			bMissing = append(bMissing, item)
		} else {
			delete(aSet, item)
		}
	}

	for item := range aSet {
		aNew = append(aNew, item)
	}

	return aNew, bMissing
}
