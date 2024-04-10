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

package controller

import (
	"errors"
	"reflect"
	"testing"

	"github.com/agiledragon/gomonkey/v2"
	"gotest.tools/assert"
)

func TestRecoverConnection(t *testing.T) {
	t.Run("test reconnect success", func(t *testing.T) {
		utClient := NewXdsClient()
		patches := gomonkey.NewPatches()
		defer patches.Reset()
		var iteration int
		patches.ApplyPrivateMethod(reflect.TypeOf(utClient), "createStreamClient",
			func(_ *XdsClient) error {
				// more than 2 link failures will result in a long test time
				if iteration < 2 {
					iteration++
					return errors.New("cant connect to client")
				} else {
					return nil
				}
			})
		utClient.recoverConnection()
		assert.Equal(t, 2, iteration)
	})
}
