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
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"testing"
)

var originalPersistPath string

func init() {
	// Save original path and use temp directory for tests
	originalPersistPath = persistPath
}

func setupTestPersistPath(t *testing.T) {
	tmpDir := t.TempDir()
	persistPath = filepath.Join(tmpDir, "hash_name.yaml")
}

func restorePersistPath() {
	persistPath = originalPersistPath
}

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
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	hashName := NewHashName()
	defer hashName.Reset()

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

		actualNum := hashName.Hash(str)
		if actualNum != expectedNum {
			t.Errorf("Hash(%s) = %d, want %d", str, actualNum, expectedNum)
		}

		// Test Number to String
		actualStr := hashName.NumToStr(actualNum)
		if actualStr != str {
			t.Errorf("NumToStr(%d) = %s, want %s", actualNum, actualStr, str)
		}
	}
}

func TestWorkloadHash_StrToNumAfterDelete(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	testStrings := []string{
		"foo", "bar", "costarring", "liquid",
	}
	strToNumMap := make(map[string]uint32)
	hashName := NewHashName()
	for _, testString := range testStrings {
		num := hashName.Hash(testString)
		strToNumMap[testString] = num
	}

	// create a new one to simulate the kmesh restart
	hashName = NewHashName()
	// Verify all strings still map to same numbers after restart
	for _, testString := range testStrings {
		actualNum := hashName.Hash(testString)
		expectedNum := strToNumMap[testString]
		if actualNum != expectedNum {
			t.Errorf("Hash(%s) = %d, want %d", testString, actualNum, expectedNum)
		}
	}

	// Now test deletion
	for _, testString := range testStrings {
		originalNum := strToNumMap[testString]
		hashName.Delete(testString)
		
		gotString := hashName.NumToStr(originalNum)
		if gotString != "" {
			t.Errorf("String of number %d should be empty after delete, but got %s", originalNum, gotString)
		}
		
		gotNum := hashName.StrToNum(testString)
		if gotNum != 0 {
			t.Errorf("Number for deleted string %s should be 0, but got %d", testString, gotNum)
		}
	}

	hashName.Reset()
}

func TestHashName_StrToNum(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	testStr := "test-string"
	expectedNum := hashName.Hash(testStr)

	actualNum := hashName.StrToNum(testStr)
	if actualNum != expectedNum {
		t.Errorf("StrToNum(%s) = %d, want %d", testStr, actualNum, expectedNum)
	}

	// Test with non-existent string
	nonExistentNum := hashName.StrToNum("non-existent")
	if nonExistentNum != 0 {
		t.Errorf("StrToNum(non-existent) = %d, want 0", nonExistentNum)
	}
}

func TestHashName_GetStrToNum(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	testStrings := []string{"alpha", "beta", "gamma"}
	for _, str := range testStrings {
		hashName.Hash(str)
	}

	strToNumMap := hashName.GetStrToNum()
	if len(strToNumMap) != len(testStrings) {
		t.Errorf("GetStrToNum() returned map with %d entries, want %d", len(strToNumMap), len(testStrings))
	}

	for _, str := range testStrings {
		if _, exists := strToNumMap[str]; !exists {
			t.Errorf("GetStrToNum() missing entry for %s", str)
		}
	}
}

func TestHashName_DeleteNonExistent(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	// Delete a string that doesn't exist - should not panic or error
	hashName.Delete("non-existent-string")

	// Verify the map is still empty
	if len(hashName.GetStrToNum()) != 0 {
		t.Errorf("Expected empty map after deleting non-existent string")
	}
}

func TestHashName_NumToStrNonExistent(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	// Test with a number that doesn't exist
	result := hashName.NumToStr(12345)
	if result != "" {
		t.Errorf("NumToStr(12345) = %s, want empty string", result)
	}
}

func TestHashName_PersistenceWithEmptyMap(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	
	// Flush empty map
	err := hashName.flush()
	if err != nil {
		t.Errorf("flush() on empty map failed: %v", err)
	}

	// Verify file exists and is empty or contains empty content
	data, err := os.ReadFile(persistPath)
	if err != nil {
		t.Errorf("Failed to read persist file: %v", err)
	}

	if len(data) > 0 && string(data) != "{}\n" && string(data) != "" {
		t.Errorf("Expected empty or {} content, got: %s", string(data))
	}

	hashName.Reset()
}

func TestHashName_PersistenceAcrossRestarts(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	// First instance
	hashName1 := NewHashName()
	testStrings := []string{"service-a", "service-b", "service-c"}
	strToNumMap := make(map[string]uint32)

	for _, str := range testStrings {
		num := hashName1.Hash(str)
		strToNumMap[str] = num
	}

	// Simulate restart by creating new instance (don't call Reset)
	hashName2 := NewHashName()

	// Verify all mappings are restored
	for _, str := range testStrings {
		expectedNum := strToNumMap[str]
		actualNum := hashName2.StrToNum(str)
		if actualNum != expectedNum {
			t.Errorf("After restart, StrToNum(%s) = %d, want %d", str, actualNum, expectedNum)
		}

		actualStr := hashName2.NumToStr(expectedNum)
		if actualStr != str {
			t.Errorf("After restart, NumToStr(%d) = %s, want %s", expectedNum, actualStr, str)
		}
	}

	hashName2.Reset()
}

func TestHashName_HashIdempotency(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	testStr := "idempotent-test"
	
	// Call Hash multiple times on the same string
	num1 := hashName.Hash(testStr)
	num2 := hashName.Hash(testStr)
	num3 := hashName.Hash(testStr)

	if num1 != num2 || num2 != num3 {
		t.Errorf("Hash is not idempotent: got %d, %d, %d", num1, num2, num3)
	}
}

func TestHashName_MultipleCollisions(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	// These strings are known to collide with fnv32a
	collidingStrings := []string{"costarring", "liquid"}
	hashValueMap := getHashValueMap(collidingStrings)

	num1 := hashName.Hash(collidingStrings[0])
	num2 := hashName.Hash(collidingStrings[1])

	// First string should get its hash value
	if num1 != hashValueMap[collidingStrings[0]] {
		t.Errorf("First colliding string hash mismatch")
	}

	// Second string should get hash+1 due to collision
	if num2 != num1+1 {
		t.Errorf("Second colliding string should be hash+1, got %d, want %d", num2, num1+1)
	}
}

func TestHashName_DeleteAndReAdd(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	testStr := "delete-readd-test"
	
	// Add string
	num1 := hashName.Hash(testStr)
	
	// Delete string
	hashName.Delete(testStr)
	
	// Verify deletion
	if hashName.NumToStr(num1) != "" {
		t.Errorf("String should be deleted but NumToStr still returns: %s", hashName.NumToStr(num1))
	}
	
	if hashName.StrToNum(testStr) != 0 {
		t.Errorf("String should be deleted but StrToNum still returns: %d", hashName.StrToNum(testStr))
	}
	
	// Re-add the same string
	num2 := hashName.Hash(testStr)
	
	// It should get the same hash value (since the slot is now free)
	if num2 != num1 {
		t.Errorf("Re-added string got different hash: got %d, want %d", num2, num1)
	}
}

func TestHashName_ReadFromCorruptedFile(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	// Write corrupted YAML to file
	corruptedData := []byte("this is not valid: yaml: content:\n  - broken")
	err := os.WriteFile(persistPath, corruptedData, 0644)
	if err != nil {
		t.Fatalf("Failed to write corrupted file: %v", err)
	}

	// Should handle corrupted file gracefully
	hashName := NewHashName()
	defer hashName.Reset()

	// Should initialize with empty maps despite corrupted file
	if len(hashName.GetStrToNum()) != 0 {
		t.Errorf("Expected empty map after reading corrupted file")
	}

	// Should still be able to add new entries
	testStr := "test-after-corruption"
	num := hashName.Hash(testStr)
	if hashName.NumToStr(num) != testStr {
		t.Errorf("Failed to add entry after handling corrupted file")
	}
}

func TestHashName_LargeDataset(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	// Test with larger dataset
	numStrings := 100
	strToNumMap := make(map[string]uint32)

	for i := 0; i < numStrings; i++ {
		str := fmt.Sprintf("service-%d", i)
		num := hashName.Hash(str)
		strToNumMap[str] = num
	}

	// Verify all mappings
	for str, expectedNum := range strToNumMap {
		actualNum := hashName.StrToNum(str)
		if actualNum != expectedNum {
			t.Errorf("Large dataset: StrToNum(%s) = %d, want %d", str, actualNum, expectedNum)
		}

		actualStr := hashName.NumToStr(expectedNum)
		if actualStr != str {
			t.Errorf("Large dataset: NumToStr(%d) = %s, want %s", expectedNum, actualStr, str)
		}
	}
}

func TestHashName_FlushDelta(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	// Add first string - triggers flushDelta
	str1 := "first-string"
	num1 := hashName.Hash(str1)

	// Add second string - triggers flushDelta again
	str2 := "second-string"
	num2 := hashName.Hash(str2)

	// Verify both are persisted by creating new instance
	hashName2 := NewHashName()
	
	if hashName2.StrToNum(str1) != num1 {
		t.Errorf("First string not persisted correctly")
	}
	
	if hashName2.StrToNum(str2) != num2 {
		t.Errorf("Second string not persisted correctly")
	}

	hashName2.Reset()
}

func TestHashName_EmptyString(t *testing.T) {
	setupTestPersistPath(t)
	defer restorePersistPath()
	
	cleanPersistFile()
	defer cleanPersistFile()

	hashName := NewHashName()
	defer hashName.Reset()

	// Test with empty string
	emptyStr := ""
	num := hashName.Hash(emptyStr)
	
	// Should still work
	if hashName.NumToStr(num) != emptyStr {
		t.Errorf("Empty string not handled correctly")
	}
	
	if hashName.StrToNum(emptyStr) != num {
		t.Errorf("Empty string StrToNum not working correctly")
	}
}