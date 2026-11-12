package source

import (
	"os"
	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
	"time"
)

func env(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func emptySnapshot(mode string, now time.Time) monitor.Snapshot {
	return monitor.Snapshot{
		Mode: mode, Updated: now,
		Hosts: []monitor.Host{}, Logs: []monitor.LogEntry{}, Alerts: []monitor.Alert{},
		Traffic: []monitor.Traffic{}, Warnings: []string{},
	}
}

func number(value float64) *float64 { return &value }
