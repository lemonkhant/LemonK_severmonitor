package source

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

type fixedRegistry []monitor.Asset

func (r fixedRegistry) List() []monitor.Asset { return r }

func TestLiveSnapshotReportsFreshAndStaleHosts(t *testing.T) {
	now := time.Date(2026, 11, 11, 4, 0, 0, 0, time.UTC)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		query := r.URL.Query().Get("query")
		switch r.URL.Path {
		case "/api/v1/query":
			fresh, stale := "36", "12"
			if strings.Contains(query, "tlast_over_time") {
				fresh = strconv.FormatInt(now.Add(-15*time.Second).Unix(), 10)
				stale = strconv.FormatInt(now.Add(-10*time.Minute).Unix(), 10)
			}
			fmt.Fprintf(w, `{"status":"success","data":{"result":[{"metric":{"host_id":"fresh"},"value":[%d,%q]},{"metric":{"host_id":"stale"},"value":[%d,%q]}]}}`, now.Unix(), fresh, now.Unix(), stale)
		case "/api/v1/query_range":
			fmt.Fprint(w, `{"status":"success","data":{"result":[]}}`)
		case "/loki/api/v1/query_range":
			body := map[string]any{"status": "success", "data": map[string]any{
				"result": []any{map[string]any{
					"stream": map[string]string{"service_name": "web"},
					"values": []any{[]any{strconv.FormatInt(now.UnixNano(), 10), "smoke", map[string]string{"host_id": "fresh"}}},
				}},
			}}
			_ = json.NewEncoder(w).Encode(body)
		default:
			http.NotFound(w, r)
		}
	}))
	defer backend.Close()
	source := &Live{
		registry: fixedRegistry{{ID: "fresh", Provider: "AWS"}, {ID: "stale", Provider: "DigitalOcean"}},
		metrics:  backend.URL, logs: backend.URL, client: backend.Client(),
	}
	snapshot := source.Snapshot(t.Context(), now, time.Hour)
	if len(snapshot.Warnings) != 0 || len(snapshot.Hosts) != 2 {
		t.Fatalf("unexpected live snapshot: %+v", snapshot)
	}
	if snapshot.Hosts[0].Status != "Healthy" || snapshot.Hosts[1].Status != "Stale" || snapshot.Hosts[1].CPU != nil {
		t.Fatalf("unexpected host status: %+v", snapshot.Hosts)
	}
	if len(snapshot.Logs) != 1 || snapshot.Logs[0].Host != "fresh" || snapshot.Logs[0].Message != "smoke" {
		t.Fatalf("unexpected live log result: %+v", snapshot.Logs)
	}
	if snapshot.AlertsConnected || len(snapshot.Alerts) != 0 {
		t.Fatal("an unconfigured alert source must stay unavailable in live mode")
	}
}
