package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

type recordingSource struct {
	window time.Duration
	calls  int
}

func (s *recordingSource) Snapshot(_ context.Context, now time.Time, window time.Duration) monitor.Snapshot {
	s.calls++
	s.window = window
	return monitor.Snapshot{Mode: "live", Updated: now}
}

func TestSnapshot(t *testing.T) {
	source := &recordingSource{}
	handler := New(source, http.NotFoundHandler(), nil, "", nil, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/snapshot?range=24h", nil))
	if response.Code != http.StatusOK || source.window != 24*time.Hour {
		t.Fatalf("status = %d, requested window = %v", response.Code, source.window)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("snapshot responses must not be cached")
	}
	var snapshot monitor.Snapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil || snapshot.Mode != "live" {
		t.Fatalf("invalid snapshot: %s", response.Body)
	}
}

func TestInvalidRangeDoesNotQuerySources(t *testing.T) {
	source := &recordingSource{}
	response := httptest.NewRecorder()
	New(source, http.NotFoundHandler(), nil, "", nil, nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/snapshot?range=30d", nil))
	if response.Code != http.StatusBadRequest || source.calls != 0 {
		t.Fatalf("status = %d, source calls = %d", response.Code, source.calls)
	}
}

func TestUnknownAPIPathDoesNotServeFrontend(t *testing.T) {
	frontend := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("unknown API path reached frontend")
	})
	response := httptest.NewRecorder()
	New(&recordingSource{}, frontend, nil, "", nil, nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/missing", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d", response.Code)
	}
}
