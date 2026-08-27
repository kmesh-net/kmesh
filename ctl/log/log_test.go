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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLoggerLevelURL(t *testing.T) {
	tests := []struct {
		name       string
		loggerName string
		want       string
	}{
		{
			name:       "plain name is unchanged",
			loggerName: "default",
			want:       "http://127.0.0.1:15200/debug/loggers?name=default",
		},
		{
			// Kmesh tags log lines with subsys values like this one, so it is a
			// plausible thing for someone to type even though it is not a
			// registered logger.
			name:       "name containing a space is escaped",
			loggerName: "cni installer",
			want:       "http://127.0.0.1:15200/debug/loggers?name=cni+installer",
		},
		{
			name:       "name containing slashes is escaped",
			loggerName: "cache/v2",
			want:       "http://127.0.0.1:15200/debug/loggers?name=cache%2Fv2",
		},
	}

	const base = "http://127.0.0.1:15200/debug/loggers"
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loggerLevelURL(base, tt.loggerName); got != tt.want {
				t.Errorf("loggerLevelURL(%q) = %q, want %q", tt.loggerName, got, tt.want)
			}
		})
	}
}

// The name must survive the round trip to the daemon. An unescaped space builds
// a malformed request line that the server rejects before routing, so the
// handler never sees the name and the caller gets a bare 400 rather than the
// daemon's own explanation.
func TestLoggerLevelURLReachesHandler(t *testing.T) {
	for _, loggerName := range []string{"default", "cni installer", "cache/v2"} {
		t.Run(loggerName, func(t *testing.T) {
			var got string
			handlerRan := false

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				handlerRan = true
				got = r.URL.Query().Get("name")
				fmt.Fprintf(w, `{"name":%q,"level":"info"}`, got)
			}))
			defer srv.Close()

			var info LoggerInfo
			if err := GetJson(loggerLevelURL(srv.URL+patternLoggers, loggerName), &info); err != nil {
				t.Fatalf("GetJson for logger %q: %v", loggerName, err)
			}

			if !handlerRan {
				t.Fatalf("the daemon handler never ran for logger %q", loggerName)
			}
			if got != loggerName {
				t.Errorf("daemon received name %q, want %q", got, loggerName)
			}
			if info.Name != loggerName {
				t.Errorf("decoded name %q, want %q", info.Name, loggerName)
			}
		})
	}
}
