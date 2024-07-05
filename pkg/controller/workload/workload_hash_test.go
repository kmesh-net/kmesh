/*
 * Copyright 2024 The Kmesh Authors.
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

package workload

import (
	"hash/fnv"
	"os"
	"testing"
)

func getHashValueMap(testStrings []string) map[string]uint32 {
	hashValueMap := make(map[string]uint32)
	hash := fnv.New32a()
	for _, testString := range testStrings {
		hash.Reset()
		hash.Write([]byte(testString))
		hashValueMap[testString] = hash.Sum32()
	}
	return hashValueMap
}

// clean persist file for test
func cleanPersistFile() {
	_ = os.Remove(persistPath)
}

func TestWorkloadHash_Basic(t *testing.T) {
	cleanPersistFile()
	hashName := NewHashName()

	// "foo" does not collide with "bar"
	// while "costarring" collides with "liquid"
	testStrings := []string{
		"foo", "bar", "costarring", "liquid",
	}
	hashValueMap := getHashValueMap(testStrings)

	testcases := []struct {
		str         string
		expectedNum uint32
	}{
		{"foo", hashValueMap["foo"]},
		{"bar", hashValueMap["bar"]},
		{"costarring", hashValueMap["costarring"]},
		// collision occurs here, so plus 1
		{"liquid", hashValueMap["costarring"] + 1},
	}

	for _, testcase := range testcases {
		str := testcase.str
		expectedNum := testcase.expectedNum

		actualNum := hashName.StrToNum(str)
		if actualNum != expectedNum {
			t.Errorf("StrToNum(%s) = %d, want %d", str, actualNum, expectedNum)
		}

		// Test Number to String
		actualStr := hashName.NumToStr(actualNum)
		if actualStr != str {
			t.Errorf("NumToStr(%d) = %s, want %s", actualNum, actualStr, str)
		}
	}
}

func TestWorkloadHash_StrToNumAfterDelete(t *testing.T) {
	cleanPersistFile()
	testStrings := []string{
		"foo", "bar", "costarring", "liquid",
	}
	strToNumMap := make(map[string]uint32)
	hashName := NewHashName()
	for _, testString := range testStrings {
		num := hashName.StrToNum(testString)
		strToNumMap[testString] = num
	}

	// create a new one to imutate the kmesh restart
	hashName = NewHashName()
	// we swap the two collided strings
	testStrings[2], testStrings[3] = testStrings[3], testStrings[2]
	for _, testString := range testStrings {
		actualNum := hashName.StrToNum(testString)
		expectedNum := strToNumMap[testString]
		if actualNum != expectedNum {
			t.Errorf("StrToNum(%s) = %d, want %d", testString, actualNum, expectedNum)
		}
	}

	for _, testString := range testStrings {
		hashName.Delete(testString)
		originalNum := strToNumMap[testString]
		gotString := hashName.NumToStr(originalNum)
		if gotString != "" {
			t.Errorf("String of number %d should be empty, but got %s", originalNum, gotString)
			return
		}
	}
}
