package workload

import (
	"hash/fnv"
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

func TestWorkloadHash_Basic(t *testing.T) {
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
	testStrings := []string{
		"foo", "bar", "costarring", "liquid",
	}
	strToNumMap := make(map[string]uint32)
	hashName := NewHashName()
	// testcase 1: call StrToNum immediately after Delete
	for _, testString := range testStrings {
		num := hashName.StrToNum(testString)
		strToNumMap[testString] = num
	}

	for _, testString := range testStrings {
		hashName.Delete(testString)
		originalNum := strToNumMap[testString]
		gotString := hashName.NumToStr(originalNum)
		if gotString != "" {
			t.Errorf("String of number %d should be empty, but got %s", originalNum, gotString)
		}
		currNum := hashName.StrToNum(testString)
		if currNum != originalNum {
			t.Errorf("StrToNum(%s) = %d, want %d", testString, currNum, originalNum)
		}
	}

	// cleanup
	for _, testString := range testStrings {
		hashName.Delete(testString)
	}

	// testcase 2: call Delete, call StrToNum with another string, then call StrToNum with this string againw
	originalNum := hashName.StrToNum("costarring")
	hashName.Delete("costarring")
	_ = hashName.StrToNum("liquid")
	currNum := hashName.StrToNum("costarring")
	if currNum != originalNum {
		t.Errorf("StrToNum(%s) = %d, want %d", "costarring", currNum, originalNum)
	}
}
