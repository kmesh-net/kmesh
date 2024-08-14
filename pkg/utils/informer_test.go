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
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetInformerFactory(t *testing.T) {
	nodeName := "test-node"
	os.Setenv("NODE_NAME", nodeName)
	defer os.Unsetenv("NODE_NAME")

	client := fake.NewSimpleClientset()

	informerFactory = nil
	once = sync.Once{}

	factory := GetInformerFactory(client)

	assert.NotNil(t, factory, "informerFactory should not be nil")

	newFactory := GetInformerFactory(client)
	assert.Equal(t, factory, newFactory, "informerFactory should be the same instance")
}
