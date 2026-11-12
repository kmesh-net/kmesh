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
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecute(t *testing.T) {
	err := Execute("echo", []string{"hello"})
	assert.NoError(t, err)

	err = Execute("false", []string{})
	assert.Error(t, err)
}

func TestExecuteWithRedirect(t *testing.T) {
	err := ExecuteWithRedirect("echo", []string{"hello"}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "stdout can not be null")

	var buf bytes.Buffer
	err = ExecuteWithRedirect("echo", []string{"hello"}, &buf)
	assert.NoError(t, err)
	assert.Contains(t, buf.String(), "hello")
}
