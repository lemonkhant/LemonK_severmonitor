package threat

import (
	"context"
	"time"

	"github.com/lemonkhant/LemonK_severmonitor/internal/monitor"
)

type Events struct {
	Logs            []monitor.LogEntry
	Alerts          []monitor.Alert
	LogsAvailable   bool
	AlertsAvailable bool
}

type EventSource interface {
	SecurityEvents(context.Context, time.Time, time.Duration) Events
}

type Rule struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Contains  string `json:"contains"`
	Threshold int    `json:"threshold"`
	Severity  string `json:"severity"`
	Enabled   bool   `json:"enabled"`
	BuiltIn   bool   `json:"builtIn"`
}

type Indicator struct {
	IP    string `json:"ip"`
	Label string `json:"label"`
}

type Detection struct {
	ID        string    `json:"id"`
	Kind      string    `json:"kind"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Host      string    `json:"host"`
	Time      time.Time `json:"time"`
	IP        string    `json:"ip,omitempty"`
	User      string    `json:"user,omitempty"`
	Technique string    `json:"technique,omitempty"`
	Count     int       `json:"count"`
	Evidence  string    `json:"evidence"`
}

type CaseEvent struct {
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Status string    `json:"status"`
	Note   string    `json:"note,omitempty"`
}

type Case struct {
	Detection Detection   `json:"detection"`
	Status    string      `json:"status"`
	History   []CaseEvent `json:"history"`
}

type Exposure struct {
	Asset       monitor.Asset `json:"asset"`
	AddressType string        `json:"addressType"`
	Logs        int           `json:"logs"`
	AuthEvents  int           `json:"authEvents"`
}

type Report struct {
	CaseLimitReached bool        `json:"caseLimitReached"`
	LogsAvailable    bool        `json:"logsAvailable"`
	AlertsAvailable  bool        `json:"alertsAvailable"`
	Detections       []Detection `json:"detections"`
	Rules            []Rule      `json:"rules"`
	Indicators       []Indicator `json:"indicators"`
	Cases            []Case      `json:"cases"`
	Exposure         []Exposure  `json:"exposure"`
}
