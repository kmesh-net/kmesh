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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServer_readyProbe(t *testing.T) {
	t.Run("nil loader and nil xdsClient returns not ready", func(t *testing.T) {
		server := &Server{}

		req := httptest.NewRequest(http.MethodGet, patternReadyProbe, nil)
		w := httptest.NewRecorder()
		server.readyProbe(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))

		var resp ReadyResponse
		err := json.Unmarshal(w.Body.Bytes(), &resp)
		assert.Nil(t, err)
		assert.False(t, resp.Ready)
		assert.Equal(t, "not initialized", resp.Components["bpf"])
		assert.Equal(t, "not initialized", resp.Components["xds_connection"])
		assert.Equal(t, "not initialized", resp.Components["controller"])
	})
}
