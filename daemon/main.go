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

package main

import (
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"kmesh.net/kmesh/pkg/logger"

	"github.com/sirupsen/logrus"

	"kmesh.net/kmesh/daemon/manager"
)

var isReady int32

// readinessHandler returns 200 if ready, 503 otherwise
func readinessHandler(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&isReady) == 1 {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("Not Ready"))
	}
}

// startReadinessServer starts an HTTP server on :8080 with /ready
func startReadinessServer(log *logrus.Entry) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ready", readinessHandler)

	go func() {
		log.Infof("Readiness server listening on :8080")
		if err := http.ListenAndServe(":8080", mux); err != nil {
			log.Errorf("Failed to start readiness server: %v", err)
		}
	}()
}

func main() {
	log := logger.NewLoggerScope("main")

	startReadinessServer(log)
	atomic.StoreInt32(&isReady, 0)

	atomic.StoreInt32(&isReady, 1)

	cmd := manager.NewCommand()
	if err := cmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	for {
		time.Sleep(10 * time.Second)
	}
}
