package threat

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

func TestDetectsSSHBurstWatchlistAndNewSource(t *testing.T) {
	now := time.Date(2026, 11, 12, 2, 0, 0, 0, time.UTC)
	entry := func(offset int, message string) monitor.LogEntry {
		return monitor.LogEntry{Host: "api", Time: now.Add(time.Duration(offset) * time.Second), Message: message}
	}
	logs := []monitor.LogEntry{
		entry(-40, "sshd[1]: Accepted publickey for ubuntu from 192.0.2.1 port 22 ssh2"),
		entry(-30, "sshd[2]: Accepted publickey for ubuntu from 192.0.2.1 port 22 ssh2"),
		entry(-20, "sshd[3]: Accepted publickey for ubuntu from 192.0.2.1 port 22 ssh2"),
		entry(15, "sshd-session[9]: Accepted publickey for ubuntu from 2001:db8::7 port 22 ssh2"),
	}
	for n := 0; n < 5; n++ {
		logs = append(logs, entry(n, "Nov 12 02:00:00 api sshd[8]: Failed password for invalid user admin from 203.0.113.7 port 1234 ssh2"))
	}
	logs = append(logs, logs[len(logs)-1], entry(16, "Application reported failed password from 203.0.113.7"))
	detections, counts := evaluate(Events{Logs: logs}, state{Indicators: []Indicator{{IP: "203.0.113.7", Label: "Test indicator"}}})
	if counts["api"] != 9 || len(detections) != 3 {
		t.Fatalf("unexpected detections: %v, auth counts: %v", detections, counts)
	}
	if !slices.ContainsFunc(detections, func(row Detection) bool {
		return row.Kind == "ssh-new-source" && row.IP == "2001:db8::7" && row.User == "ubuntu"
	}) || !slices.ContainsFunc(detections, func(row Detection) bool {
		return row.Kind == "ssh-brute-force" && row.Count == 5
	}) {
		t.Fatalf("expected new source and failed sign-in correlation, got %v", detections)
	}
}

func TestPersistsRulesAndDeduplicatesCases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "security.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rule := Rule{Name: "Application error", Contains: "critical error", Threshold: 1, Severity: "High", Enabled: true}
	if err := store.SaveRule("", rule); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	detections, _ := evaluate(Events{Logs: []monitor.LogEntry{{Host: "app", Time: now, Message: "Critical Error"}}}, store.snapshot())
	if len(detections) != 1 {
		t.Fatalf("expected one detection, got %v", detections)
	}
	if err := store.openCases(detections, "Automation", now); err != nil {
		t.Fatal(err)
	}
	if err := store.openCases(detections, "Admin", now); err != nil {
		t.Fatal(err)
	}
	if err := store.UpdateCase(detections[0].ID, "Resolved", "Reviewed", now); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	data := reopened.snapshot()
	if len(data.Rules) != 1 || len(data.Cases) != 1 || len(data.Cases[0].History) != 2 || data.Cases[0].Status != "Resolved" {
		t.Fatalf("unexpected persisted state: %+v", data)
	}
}
