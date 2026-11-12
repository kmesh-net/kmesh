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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAtomicWriteAndCopy(t *testing.T) {
	tempDir := t.TempDir()
	sourceFile := filepath.Join(tempDir, "source.txt")
	targetFile := "target.txt"

	data := []byte("hello kmesh")
	err := AtomicWrite(sourceFile, data, 0644)
	assert.NoError(t, err)

	content, err := os.ReadFile(sourceFile)
	assert.NoError(t, err)
	assert.Equal(t, string(data), string(content))

	err = AtomicCopy(sourceFile, tempDir, targetFile)
	assert.NoError(t, err)

	copiedContent, err := os.ReadFile(filepath.Join(tempDir, targetFile))
	assert.NoError(t, err)
	assert.Equal(t, string(data), string(copiedContent))
}
