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
