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

package logs

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetchLoggerNames(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		want := []string{"default", "bpf"}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.NoError(t, json.NewEncoder(w).Encode(want))
		}))
		defer server.Close()

		got, err := FetchLoggerNames(server.URL)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("non-200", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("bad"))
		}))
		defer server.Close()

		_, err := FetchLoggerNames(server.URL)
		require.Error(t, err)
	})
}

func TestFetchLoggerLevel(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		want := LoggerInfo{Name: "default", Level: "info"}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "default", r.URL.Query().Get("name"))
			require.NoError(t, json.NewEncoder(w).Encode(want))
		}))
		defer server.Close()

		got, err := FetchLoggerLevel(server.URL + "?name=default")
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("invalid json", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("{"))
		}))
		defer server.Close()

		_, err := FetchLoggerLevel(server.URL)
		require.Error(t, err)
	})
}
