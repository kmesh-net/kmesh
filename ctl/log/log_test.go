package logs_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	logs "kmesh.net/kmesh/ctl/log"
)

// TestGetJson_Success verifies GetJson can unmarshal valid JSON
func TestGetJson_Success(t *testing.T) {
	mockData := []string{"logger1", "logger2"}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respBytes, _ := json.Marshal(mockData)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)
	}))
	defer ts.Close()

	var result []string
	err := logs.GetJson(ts.URL, &result)
	if err != nil {
		t.Fatalf("GetJson failed: %v", err)
	}
	if len(result) != 2 || result[0] != "logger1" || result[1] != "logger2" {
		t.Errorf("Unexpected result: got %#v, want [logger1, logger2]", result)
	}
}

// TestGetJson_Failure verifies GetJson handles HTTP errors and bad JSON properly.
func TestGetJson_Failure(t *testing.T) {
	// 1) Server returns an internal error
	tsError := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "something went wrong", http.StatusInternalServerError)
	}))
	defer tsError.Close()

	var result []string
	err := logs.GetJson(tsError.URL, &result)
	if err == nil || !strings.Contains(err.Error(), "status code 500") {
		t.Errorf("Expected an HTTP 500 error, got: %v", err)
	}

	// 2) Server returns invalid JSON
	tsBadJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{invalid-json"))
	}))
	defer tsBadJSON.Close()

	err = logs.GetJson(tsBadJSON.URL, &result)
	if err == nil || !strings.Contains(err.Error(), "failed to unmarshal") {
		t.Errorf("Expected unmarshal error, got: %v", err)
	}
}

// TestSetLoggerLevel_Success checks the normal flow of SetLoggerLevel (no exit).
func TestSetLoggerLevel_Success(t *testing.T) {
	wantLoggerName := "default"
	wantLoggerLevel := "debug"

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify it was a POST
		if r.Method != http.MethodPost {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		defer r.Body.Close()

		var info logs.LoggerInfo
		data, _ := io.ReadAll(r.Body)
		json.Unmarshal(data, &info)

		// Check the posted data
		if info.Name != wantLoggerName {
			t.Errorf("Expected logger name %q, got %q", wantLoggerName, info.Name)
		}
		if info.Level != wantLoggerLevel {
			t.Errorf("Expected logger level %q, got %q", wantLoggerLevel, info.Level)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("All good"))
	}))
	defer ts.Close()

	oldStdout := os.Stdout
	r, wPipe, _ := os.Pipe()
	os.Stdout = wPipe
	logs.SetLoggerLevel(ts.URL, wantLoggerName+":"+wantLoggerLevel)

	_ = wPipe.Close()
	os.Stdout = oldStdout

	out, _ := io.ReadAll(r)
	output := string(out)

	if !strings.Contains(output, "All good") {
		t.Errorf("Expected 'All good' in output, got: %s", output)
	}
}
