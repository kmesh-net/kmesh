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

package status

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	istiosecurity "istio.io/istio/pkg/security"
)

func TestConvertSecretItem(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result := ConvertSecretItem(nil)
		assert.Nil(t, result)
	})

	t.Run("valid input converts correctly", func(t *testing.T) {
		now := time.Now()
		expire := now.Add(24 * time.Hour)
		item := &istiosecurity.SecretItem{
			ResourceName:     "default",
			CertificateChain: []byte("cert-chain-data"),
			ExpireTime:       expire,
			CreatedTime:      now,
		}

		result := ConvertSecretItem(item)
		assert.NotNil(t, result)
		assert.Equal(t, "default", result.ResourceName)
		assert.Equal(t, "cert-chain-data", result.CertificateChain)
		assert.Equal(t, expire, result.ExpireTime)
		assert.Equal(t, now, result.CreatedTime)
	})
}
