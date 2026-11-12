package monitor

import (
	"context"
	"time"
)

type Asset struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Provider string `json:"provider"`
	Region   string `json:"region"`
	Address  string `json:"address,omitempty"`
	SSHUser  string `json:"sshUser,omitempty"`
}

type Host struct {
	Asset
	Status string     `json:"status"`
	CPU    *float64   `json:"cpu"`
	Memory *float64   `json:"memory"`
	Disk   *float64   `json:"disk"`
	Seen   *time.Time `json:"seen"`
}

type LogEntry struct {
	Time    time.Time `json:"time"`
	Host    string    `json:"host"`
	Service string    `json:"service"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

type Alert struct {
	ID       string    `json:"id"`
	Time     time.Time `json:"time"`
	Host     string    `json:"host"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	Detail   string    `json:"detail"`
}

type Point struct {
	Time time.Time `json:"time"`
	RX   *float64  `json:"rx"`
	TX   *float64  `json:"tx"`
}

type Traffic struct {
	Provider string  `json:"provider"`
	Points   []Point `json:"points"`
}

type Snapshot struct {
	Mode            string     `json:"mode"`
	Updated         time.Time  `json:"updated"`
	Hosts           []Host     `json:"hosts"`
	Logs            []LogEntry `json:"logs"`
	Alerts          []Alert    `json:"alerts"`
	Traffic         []Traffic  `json:"traffic"`
	Warnings        []string   `json:"warnings"`
	AlertsConnected bool       `json:"alertsConnected"`
}

// Source provides one dashboard snapshot for the requested time window.
type Source interface {
	Snapshot(ctx context.Context, now time.Time, window time.Duration) Snapshot
}
