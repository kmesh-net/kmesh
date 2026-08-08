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

package version

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgversion "kmesh.net/kmesh/pkg/version"
)

func TestFetchVersion(t *testing.T) {
	want := pkgversion.Info{
		GitVersion: "v1.2.0",
		GitCommit:  "abc123",
	}

	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/version", r.URL.Path)
			require.NoError(t, json.NewEncoder(w).Encode(want))
		}))
		defer server.Close()

		got, err := FetchVersion(server.URL + "/version")
		require.NoError(t, err)
		assert.Equal(t, want.GitVersion, got.GitVersion)
		assert.Equal(t, want.GitCommit, got.GitCommit)
	})

	t.Run("non-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("boom"))
		}))
		defer server.Close()

		_, err := FetchVersion(server.URL + "/version")
		require.Error(t, err)
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not-json"))
		}))
		defer server.Close()

		_, err := FetchVersion(server.URL + "/version")
		require.Error(t, err)
	})
}
